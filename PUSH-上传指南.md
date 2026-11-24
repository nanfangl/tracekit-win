# 上传到 GitHub：照着做就行

> 这台机器**完全没有外网**（github.com / gitee.com / baidu.com 全部连不上），也没有 git、gh，
> 没有任何令牌。所以我把仓库**准备到"一条 push 就完事"的状态**，你在能上网的机器上执行下面几步即可。
>
> 两种搬走方式：
> - **A**：把整个 `TraceKit-github` 文件夹拷到能上网的电脑（U 盘/网盘/微信），在那边推送
> - **B**：就在这台机器上先装 git、连上代理/网络，再推送（步骤一样）

---

## 〇、推之前先替换 2 处占位符（30 秒）

README 里的徽章和 clone 地址写的是 `OWNER`，改成你的用户名：

```powershell
cd TraceKit-github
(Get-Content README.md -Raw) -replace 'OWNER', '<你的GitHub用户名>' | Set-Content README.md -Encoding UTF8
```

确认一下：`git --version`（没有就先装：`winget install --id Git.Git -e`）。

---

## 一、先想清楚三件事（30 秒）

| 项 | 建议 |
| --- | --- |
| 仓库名 | `tracekit-win`（PyPI 上 `tracekit` 可能被占，仓库名带 `-win` 更清晰） |
| 公开/私有 | 想让人用就 **Public**；只想自己留着就 **Private**（CI 与 Release 都能用） |
| 许可证 | 已放 **MIT**（`LICENSE`），如需商用限制请自行替换 |

---

## 二、方式 A：本机已有 git（最稳）

```powershell
cd TraceKit-github

git init -b main
git add -A
git commit -m "feat: TraceKit 1.0.0 —— Windows 软件行为记录器（16 层采集 + 可视化向导）"

# 先在网页上建一个空仓库（不要勾 README/License），拿到地址后：
git remote add origin https://github.com/<你的用户名>/tracekit-win.git
git branch -M main
git push -u origin main
```

`git push` 时会问账号密码 —— **密码处必须填 Personal Access Token**：

1. GitHub 头像 → Settings → Developer settings → **Personal access tokens → Tokens (classic)**
2. Generate new token (classic) → 勾 **`repo`**（私有仓库还要 `workflow`）→ 有效期自选
3. 复制 `ghp_xxx`，在密码提示处粘贴（只显示一次，别丢）

或者用 **SSH**（更省事，一次配好永久用）：

```powershell
ssh-keygen -t ed25519 -C "you@example.com"      # 一路回车
type $env:USERPROFILE\.ssh\id_ed25519.pub        # 复制这一行
# GitHub → Settings → SSH and GPG keys → New SSH key → 粘贴
# 然后把 remote 换成 SSH：
git remote set-url origin git@github.com:<你的用户名>/tracekit-win.git
git push -u origin main
```

---

## 三、方式 B：用 gh CLI（两条命令）

```powershell
winget install --id GitHub.cli -e
gh auth login                       # 选 GitHub.com → HTTPS → 浏览器登录
cd TraceKit-github
gh repo create tracekit-win --public --source=. --remote=origin --push
```

一条命令建仓库 + 推送，省掉网页建库。

---

## 四、方式 C：不想装 git（网页拖拽）

1. GitHub → New repository → 名字 `tracekit-win` → Create
2. 仓库页 → **Add file → Upload files**
3. 把 `TraceKit-github` 里的**所有内容**（不是文件夹本身）拖进去，注意保留目录结构：
   `tracekit/`、`tools/`、`docs/`、`assets/`、`.github/`、以及根目录那些文件
4. 提交信息随便写，Commit changes

⚠️ 网页上传**单文件上限 25MB、单次 100 个文件**。本仓库约 45 个文件、最大 70KB（`report.py`），完全够。
**不要**把 `runs/`、`dist/`、`演示数据/`、`TraceKit.exe` 传上去（`.gitignore` 已经把它们排除了）。

用我写的脚本更省事（有 git 就行）：

```powershell
cd TraceKit-github
powershell -ExecutionPolicy Bypass -File push.ps1 -RepoUrl https://github.com/<你>/tracekit-win.git `
    -UserName "你的名字" -UserEmail "you@example.com"
```

---

## 五、推上去之后建议做的四件事

1. **建 Release 附 EXE**（36.7MB，超过网页直传上限，但 Release 附件支持 2GB）
   `Releases → Draft a new release → tag v1.0.0 → 上传 dist\TraceKit.exe 与 TraceKitDemo.exe`
   在 README 里加一行下载链接：
   `https://github.com/<你>/tracekit-win/releases/latest`
2. **填 About**：描述用这句（英文，方便被搜到）
   `Windows behavior recorder: files(read/write), registry, network, UI tree, clicks & responses, logs, DLLs, system changes — all from outside the target, no injection. Zero dependencies (ctypes).`
   Topics：`windows` `etw` `monitoring` `forensics` `reverse-engineering` `easy-language` `vmprotect` `gui-testing` `python` `ctypes`
3. **确认 CI 绿**：Actions 里应有 `ci` 跑通（编译 + 探针 + 录一段 cmd.exe + 断言 + 上传产物）
4. **把 README 顶部的截图路径确认一下**：`docs/screenshots/wizard.png` 等（仓库里已按此结构放好）

---

## 六、安全提醒（写完就忘会出事）

- **不要把 PAT 写进任何文件**，也不要 commit `.env` / `*.token`
- 如果误把令牌推上去了：立刻在 GitHub 撤销该 token，并 `git filter-repo` 清历史
- 记录产物（`runs/`）里可能有别人的文件内容副本、按键、剪贴板文字 —— **永远不要提交**
  （`.gitignore` 已排除，但用 `git add -f` 就能绕过，注意别手滑）
- 仓库是 Public 时，`SECURITY.md` 里的用途边界建议保留 —— 这类工具很容易被误解

---

## 七、这台机器上的仓库现在长什么样

```
TraceKit-github/
├─ tracekit/            24 个模块（cli / gui / core / winapi / 16 个采集器 / report）
├─ tools/               验证与演示脚本（demo_run、db_report、verify_outputs、q、ci_assert…）
├─ docs/screenshots/    6 张界面截图（wizard / recording / demo-window / keys / clipboard / timeline）
├─ assets/tracekit.ico  图标
├─ .github/workflows/ci.yml   Windows CI：编译 + 探针 + 轻量录制 + 断言 + 产物上传
├─ build_exe.ps1        一条命令出 EXE
├─ push.ps1             一条命令推送
├─ demo_victim.py       演示靶程序（也是 selftest 的被测对象）
├─ TraceKit_main.py     PyInstaller 入口
├─ pyproject.toml       pip install . 之后有 tracekit / tracekit-gui 两个命令
├─ README.md            主文档（含能力矩阵、全场景对照表、编码约定）
├─ 使用说明.txt          给最终用户的中文说明
├─ SECURITY.md          用途边界 / 数据处理 / 已知限制
├─ CHANGELOG.md         1.0.0 变更
├─ LICENSE              MIT
└─ .gitignore           已排除 runs/ dist/ *.exe __pycache__ 等
```

---

## 附：为什么不用 PyPI 发布

`pip install tracekit-win` 也能做（`pyproject.toml` 里已经配好 `tracekit` / `tracekit-gui` 两个入口），
但要额外：注册 PyPI 账号 → `python -m build` → `twine upload dist/*` → 每次发新版重复。
对"给具体的人用的工具"来说，**Release 里挂 EXE + 源码 zip** 最省事，PyPI 可以以后再说。
