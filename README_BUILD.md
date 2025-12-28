# 构建说明

## GitHub Actions 自动构建

本项目使用 GitHub Actions 自动构建 Windows 可执行文件。

### 触发构建

#### 方式1: 推送标签（推荐）
```bash
git tag v2.2.0
git push origin v2.2.0
```

推送标签后，GitHub Actions 会自动：
1. 构建 Windows 可执行文件
2. 创建发布包（ZIP 文件）
3. 自动创建 GitHub Release
4. 上传构建产物

#### 方式2: 手动触发
1. 进入 GitHub 仓库的 Actions 页面
2. 选择 "Build Windows Executable" 工作流
3. 点击 "Run workflow"
4. 选择分支并运行

### 构建产物

构建完成后，可以在以下位置找到构建产物：

1. **GitHub Actions Artifacts**
   - 进入 Actions 页面
   - 选择对应的构建任务
   - 下载 `windows-executable` artifact

2. **GitHub Release**（仅标签触发时）
   - 进入 Releases 页面
   - 下载对应版本的 ZIP 文件

### 本地构建

如果需要本地构建，可以运行：

```bash
# 安装依赖
pip install -r requirements.txt
pip install pyinstaller

# 构建
pyinstaller --clean --noconfirm hosts_optimizer_gui.spec
```

构建产物位于 `dist/` 目录。

### 构建配置

- **PyInstaller 配置文件**: `hosts_optimizer_gui.spec`
- **版本信息**: `version_info.txt`
- **图标文件**: `favicon.ico`

### 注意事项

1. 构建需要 Windows 环境（GitHub Actions 使用 `windows-latest`）
2. 确保 `version_info.txt` 中的版本号与标签版本一致
3. 构建产物会自动包含所有依赖，无需额外安装 Python

