"""Sync this repository with GitHub through the REST API.

Why this exists: in this environment `github.com:443` is blocked (plain
`git fetch` / `git push` die with "Connection was reset" or
"Failed to connect to github.com:443"), while `api.github.com` is reachable.
So git objects are moved through the Git Data API instead of the smart-HTTP
transport.

  python tools/git-api-sync.py push [<commit> ...]   replay local commits
  python tools/git-api-sync.py fetch [<sha>]         pull remote commits down
  python tools/git-api-sync.py status                compare local vs remote

Push replays the commits byte-for-byte: the message is read from the raw
commit object and decoded as UTF-8 explicitly (subprocess with text=True uses
the system locale -- GBK here -- and silently mangles Chinese commit messages
into replacement characters, which changes the SHA).  A correct replay lands
on the *same* SHA as the local commit, and the script asserts that.

Fetch walks back from the remote tip until it reaches a commit we already
have, downloads only that delta, and writes the objects into the local object
database, so history is preserved rather than flattened into a snapshot.

Two things about the REST API make byte-exact reconstruction non-obvious, and
both are handled below:

  * It normalises author/committer dates to UTC ("...Z"), so the original
    timezone offset is gone.  Offsets that appear in the local history are
    tried first, then a list of common ones -- the first candidate that hashes
    to the expected SHA wins.

  * It drops the trailing newline of the commit message.  Both variants are
    tried, because a repository's very first commit frequently has no trailing
    newline while every later one does.

Candidate bodies are hashed without being written, so the search does not
leave dangling commits behind.
"""
import base64
import datetime
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.error
import urllib.request

REPO = "isTurn/DllInjectorTest"
API = "https://api.github.com"
BRANCH = "main"


# --------------------------------------------------------------------------
# plumbing
# --------------------------------------------------------------------------
def token():
    try:
        out = subprocess.run(["gh", "auth", "token"], capture_output=True, check=True)
        return out.stdout.decode("ascii").strip()
    except (OSError, subprocess.CalledProcessError):
        raise SystemExit("no GitHub token: run `gh auth login` first")


TOKEN = token()


def api(method, path, payload=None, attempts=8):
    """Call the REST API, retrying transient connection failures.

    api.github.com is reachable from this environment but only
    intermittently: a large share of fresh connections stall for ~21 s and
    then fail with WinError 10060 (TCP connect timeout).  The failure is per
    connection, not per request, so simply retrying usually succeeds within a
    couple of tries.  Without this, a fetch of a few dozen blobs fails
    somewhere in the middle and leaves a half-populated object database.
    """
    url = API + path
    data = json.dumps(payload).encode() if payload is not None else None
    last = None
    for i in range(attempts):
        req = urllib.request.Request(url, data=data, method=method)
        req.add_header("Authorization", "Bearer " + TOKEN)
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        if data:
            req.add_header("Content-Type", "application/json")
        try:
            with urllib.request.urlopen(req, timeout=60) as r:
                return json.loads(r.read().decode())
        except urllib.error.HTTPError as e:
            # 4xx/5xx 里只有 5xx 与 429 值得重试；其余是请求本身的问题。
            body = e.read().decode(errors="replace")
            if e.code not in (429, 500, 502, 503, 504):
                raise SystemExit("HTTP %s on %s %s\n%s" % (e.code, method, path, body))
            last = "HTTP %s: %s" % (e.code, body[:200])
        except (urllib.error.URLError, OSError) as e:
            last = str(e)
        if i + 1 < attempts:
            time.sleep(min(1.5 * (i + 1), 8))
    raise SystemExit("giving up on %s %s after %d attempts: %s"
                     % (method, path, attempts, last))


def git(*args, binary=False):
    out = subprocess.run(["git"] + list(args), capture_output=True)
    if out.returncode != 0:
        raise SystemExit("git %s failed:\n%s"
                         % (" ".join(args), out.stderr.decode(errors="replace")))
    return out.stdout if binary else out.stdout.decode("utf-8")


def have(sha):
    return subprocess.run(["git", "cat-file", "-e", sha + "^{commit}"],
                          capture_output=True).returncode == 0


def remote_tip():
    return api("GET", "/repos/%s/git/ref/heads/%s" % (REPO, BRANCH))["object"]["sha"]


# --------------------------------------------------------------------------
# push
# --------------------------------------------------------------------------
def raw_commit(sha):
    raw = git("cat-file", "commit", sha, binary=True).decode("utf-8")
    head, _, message = raw.partition("\n\n")
    info = {"parents": [], "message": message}
    for line in head.split("\n"):
        if line.startswith("tree "):
            info["tree"] = line[5:]
        elif line.startswith("parent "):
            info["parents"].append(line[7:])
        elif line.startswith("author "):
            info["author"] = line[7:]
        elif line.startswith("committer "):
            info["committer"] = line[10:]
    return info


def split_ident(s):
    lt, gt = s.rindex("<"), s.rindex(">")
    ts, tz = s[gt + 1:].strip().split()
    off = datetime.timedelta(hours=int(tz[1:3]), minutes=int(tz[3:5]))
    if tz[0] == "-":
        off = -off
    dt = datetime.datetime.fromtimestamp(int(ts), datetime.timezone(off))
    return {"name": s[:lt].strip(), "email": s[lt + 1:gt], "date": dt.isoformat()}


def changes(sha):
    parts = git("diff-tree", "--no-commit-id", "--name-status", "-r", "-z", sha).split("\x00")
    out, i = [], 0
    while i < len(parts):
        st = parts[i].strip()
        if not st:
            i += 1
        elif st[0] in ("R", "C"):
            out.append((st[0], parts[i + 1], parts[i + 2]))
            i += 3
        else:
            out.append((st[0], parts[i + 1], None))
            i += 2
    return out


def mode_of(sha, path):
    raw = git("ls-tree", sha, "--", path).strip()
    return raw.split()[0] if raw else "100644"


def upload_blob(commit, path):
    data = git("cat-file", "blob", "%s:%s" % (commit, path), binary=True)
    return api("POST", "/repos/%s/git/blobs" % REPO,
               {"content": base64.b64encode(data).decode(),
                "encoding": "base64"})["sha"]


def cmd_push(argv):
    if not argv:
        # everything reachable from HEAD but not from the remote tip
        tip = remote_tip()
        argv = git("rev-list", "--reverse", "%s..HEAD" % tip).split()
        if not argv:
            print("nothing to push: remote %s already contains HEAD" % tip[:10])
            return
        print("pushing %d commit(s) on top of %s" % (len(argv), tip[:10]))

    base = remote_tip()
    tree = api("GET", "/repos/%s/git/commits/%s" % (REPO, base))["tree"]["sha"]
    replayed = {}

    for commit in argv:
        info = raw_commit(commit)
        parent = info["parents"][0] if info["parents"] else None
        if parent and parent != base and replayed.get(parent) != base:
            raise SystemExit("parent of %s is %s, remote is %s -- refusing to "
                             "rewrite history" % (commit, parent, base))

        entries = []
        for st, path, _ in changes(commit):
            if st == "D":
                entries.append({"path": path, "mode": "100644",
                                "type": "blob", "sha": None})
            else:
                entries.append({"path": path, "mode": mode_of(commit, path),
                                "type": "blob", "sha": upload_blob(commit, path)})

        tree = api("POST", "/repos/%s/git/trees" % REPO,
                   {"base_tree": tree, "tree": entries})["sha"]
        if tree != info["tree"]:
            raise SystemExit("tree mismatch for %s: built %s, local %s"
                             % (commit, tree, info["tree"]))

        new = api("POST", "/repos/%s/git/commits" % REPO, {
            "message": info["message"], "tree": tree, "parents": [base],
            "author": split_ident(info["author"]),
            "committer": split_ident(info["committer"])})["sha"]

        replayed[commit] = new
        base = new
        note = "identical" if new == commit else "DIFFERENT -- byte mismatch!"
        print("  %s -> %s (%s)" % (commit[:10], new[:10], note))
        if new != commit:
            raise SystemExit("replayed commit differs from local; aborting "
                             "before moving the branch")

    api("PATCH", "/repos/%s/git/refs/heads/%s" % (REPO, BRANCH),
        {"sha": base, "force": False})
    print("%s -> %s" % (BRANCH, base))


# --------------------------------------------------------------------------
# fetch
# --------------------------------------------------------------------------
def _hash_object(kind, data):
    out = subprocess.run(["git", "hash-object", "-w", "-t", kind, "--stdin"],
                         input=data, capture_output=True)
    if out.returncode != 0:
        raise SystemExit("hash-object failed: %s" % out.stderr.decode(errors="replace"))
    return out.stdout.decode().strip()


def _object_sha(kind, data):
    """Compute the SHA-1 of a git object without writing it.

    Used to test candidate commit bodies: the offset search below may try a
    dozen variations, and writing each loser into the object database would
    litter the repo with dangling commits.
    """
    return hashlib.sha1(b"%s %d\x00" % (kind.encode(), len(data)) + data).hexdigest()


def fetch_tree(tree_sha):
    """Download a tree and everything under it; returns True if anything new."""
    if subprocess.run(["git", "cat-file", "-e", tree_sha],
                      capture_output=True).returncode == 0:
        return False

    data = api("GET", "/repos/%s/git/trees/%s" % (REPO, tree_sha))
    body, fresh = bytearray(), False
    for e in data["tree"]:
        mode, typ, sha, path = e["mode"], e["type"], e["sha"], e["path"]
        if typ == "tree":
            fresh |= fetch_tree(sha)
        elif typ == "blob":
            if subprocess.run(["git", "cat-file", "-e", sha],
                              capture_output=True).returncode != 0:
                blob = api("GET", "/repos/%s/git/blobs/%s" % (REPO, sha))
                content = base64.b64decode(blob["content"])
                got = _hash_object("blob", content)
                if got != sha:
                    raise SystemExit("blob %s hashed to %s" % (sha, got))
                fresh = True
        # git 的 tree 对象是二进制的："<mode> <name>\0<20 字节原始 sha>"。
        # 注意 mode：GitHub API 给目录返回 "040000"，而 git 的 tree 里写的是
        # "40000" —— 零填充的 mode 会被 fsck 判成 zeroPaddedFilemode 并拒绝写入。
        body += ("%s %s" % (mode.lstrip("0") or "0", path)).encode() + b"\x00" + bytes.fromhex(sha)

    got = _hash_object("tree", bytes(body))
    if got != tree_sha:
        raise SystemExit("tree %s rebuilt as %s" % (tree_sha, got))
    return fresh


def fetch_commit(sha):
    if have(sha):
        return False
    data = api("GET", "/repos/%s/git/commits/%s" % (REPO, sha))
    for p in data["parents"]:
        fetch_commit(p["sha"])
    fetch_tree(data["tree"]["sha"])

    # GitHub 的 REST API 把 author/committer 日期归一化成 UTC 返回（"…Z"），
    # 原始的时区偏移**丢失**了。本地提交是 `… 1788250831 +0800`，API 只告诉
    # 我们时间戳 1788250831 —— 偏移是 +0800 还是 +0000 得靠试。
    # 于是这里对「偏移」做候选搜索：先试本地仓库里出现过的偏移（最可能命中，
    # 通常第一次就中），再退到一组常见值。这是唯一能保证 SHA 逐字节一致的
    # 办法 —— 否则建出来的历史会和远端分叉。
    offsets = _offset_candidates()
    a_cands = _ident_candidates(data["author"], offsets)
    c_cands = _ident_candidates(data["committer"], offsets)

    # API 还会吃掉 message 末尾的换行（本地 2857 字符的消息读回来是 2856），
    # 但仓库的第一个提交往往**本来就没有**结尾换行。所以两种都试。
    msgs = (data["message"], data["message"] + "\n")

    tree_line = "tree %s\n" % data["tree"]["sha"]
    for p in data["parents"]:
        tree_line += "parent %s\n" % p["sha"]

    def attempt(a, c):
        head = "%sauthor %s\ncommitter %s\n\n" % (tree_line, a, c)
        for m in msgs:
            body = (head + m).encode("utf-8")
            # 只算哈希、不落库：候选组合有十几个，写进去全是 dangling commit。
            if _object_sha("commit", body) == sha:
                _hash_object("commit", body)
                return True
        return False

    # 作者和提交者偏移通常相同，先试对角线，命中率最高、代价最小。
    for i in range(len(offsets)):
        if attempt(a_cands[i], c_cands[i]):
            return True
    for a in a_cands:
        for c in c_cands:
            if attempt(a, c):
                return True
    raise SystemExit("commit %s could not be rebuilt byte-for-byte" % sha)


def _ident_candidates(d, offsets):
    dt = datetime.datetime.fromisoformat(d["date"].replace("Z", "+00:00"))
    ts = int(dt.timestamp())
    return ["%s <%s> %d %s" % (d["name"], d["email"], ts, off) for off in offsets]


def _offset_candidates():
    """候选时区偏移：本地历史里见过的优先，然后是一组常见值。"""
    seen = []
    try:
        out = subprocess.run(["git", "log", "--all", "--format=%ai%n%ci"],
                             capture_output=True).stdout.decode("utf-8", "replace")
    except Exception:
        out = ""
    for line in out.splitlines():
        m = re.search(r"([+-]\d{4})\s*$", line.strip())
        if m and m.group(1) not in seen:
            seen.append(m.group(1))
    for off in ("+0000", "+0800", "-0700", "+0900", "+0100", "+0200",
                "+0530", "+1000", "-0500", "+1200", "-0800"):
        if off not in seen:
            seen.append(off)
    return seen


def cmd_fetch(argv):
    tip = remote_tip()
    target = argv[0] if argv else tip
    print("remote %s = %s" % (BRANCH, target))

    # 注意不能因为 fetch_commit() 返回 False 就提前 return：它只说明**对象**
    # 已经在库里了，不代表分支指向它。本地回退过、或者刚 clone 完又 reset 过
    # 的时候，提交对象都在、分支却是落后的，提前 return 会让 fetch 变成
    # 「说已是最新、但什么都没更新」。
    fresh = fetch_commit(target)
    if not fresh:
        print("objects already present")

    if target != tip:
        print("fetched %s" % target[:10])
        return

    subprocess.run(["git", "update-ref", "refs/remotes/origin/%s" % BRANCH, tip])
    probe = subprocess.run(["git", "rev-parse", "--verify", "--quiet",
                            "refs/heads/%s" % BRANCH], capture_output=True, text=True)
    if probe.returncode != 0:
        # 本地还没有这个分支（空仓库 / 新克隆）——直接建出来
        subprocess.run(["git", "update-ref", "refs/heads/%s" % BRANCH, tip])
        print("%s created at %s" % (BRANCH, tip[:10]))
    else:
        local = probe.stdout.strip()
        if local == tip:
            print("%s already at %s" % (BRANCH, tip[:10]))
        elif subprocess.run(["git", "merge-base", "--is-ancestor", local, tip],
                            capture_output=True).returncode == 0:
            subprocess.run(["git", "update-ref", "refs/heads/%s" % BRANCH, tip])
            print("%s fast-forwarded to %s" % (BRANCH, tip[:10]))
        else:
            print("%s is not a fast-forward of %s -- fetched but not merged"
                  % (BRANCH, local[:10]))
    print("fetched %s" % target[:10])


def cmd_status(argv):
    tip = remote_tip()
    local = git("rev-parse", BRANCH).strip()
    print("local  %s %s" % (BRANCH, local))
    print("remote %s %s" % (BRANCH, tip))
    if local == tip:
        print("in sync")
        return
    ahead = git("rev-list", "--count", "%s..%s" % (tip, local)).strip()
    behind = git("rev-list", "--count", "%s..%s" % (local, tip)).strip()
    print("ahead %s, behind %s" % (ahead, behind))


def main(argv):
    if not argv:
        raise SystemExit(__doc__)
    cmd, rest = argv[0], argv[1:]
    handlers = {"push": cmd_push, "fetch": cmd_fetch, "status": cmd_status}
    if cmd not in handlers:
        raise SystemExit(__doc__)
    handlers[cmd](rest)


if __name__ == "__main__":
    main(sys.argv[1:])
