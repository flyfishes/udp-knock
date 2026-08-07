#!/bin/bash
# 同步到GitHub的脚本

set -e

echo "🔄 开始同步到GitHub..."

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查git是否安装
if ! command -v git &> /dev/null; then
    echo -e "${RED}错误: git未安装${NC}"
    exit 1
fi

# 检查是否在git仓库中
if ! git rev-parse --git-dir > /dev/null 2>&1; then
    echo -e "${YELLOW}初始化git仓库...${NC}"
    git init
    git branch -M main
fi

# 检查远程仓库
if ! git remote get-url origin > /dev/null 2>&1; then
    echo -e "${YELLOW}未配置远程仓库，请设置:${NC}"
    echo "git remote add origin https://github.com/你的用户名/udp-knock.git"
    exit 1
fi

# 添加所有文件
echo -e "${GREEN}添加文件...${NC}"
git add .

# 检查是否有更改
if git diff --staged --quiet; then
    echo -e "${YELLOW}没有更改需要提交${NC}"
else
    # 提交更改
    echo -e "${GREEN}提交更改...${NC}"
    read -p "请输入提交信息 (默认: Update): " commit_msg
    commit_msg=${commit_msg:-Update}
    git commit -m "$commit_msg"
fi

# 拉取最新更改
echo -e "${GREEN}拉取远程更改...${NC}"
git pull origin main --rebase || echo -e "${YELLOW}无法拉取，可能远程仓库为空${NC}"

# 推送到GitHub
echo -e "${GREEN}推送到GitHub...${NC}"
git push origin main

echo -e "${GREEN}✅ 同步完成！${NC}"