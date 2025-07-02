#!/bin/bash

# 처리할 경로 목록
INPUT_PATHS=(
"/SARD-vs-CVE/CWE78_OS_CI/CVE-2017-15108/vd_agent"
"/SARD-vs-CVE/CWE78_OS_CI/CVE-2017-15924/shadowsocks-libev"
"/SARD-vs-CVE/CWE78_OS_CI/CVE-2018-16863/ghostpdl"
"/SARD-vs-CVE/CWE78_OS_CI/CVE-2018-6791/plasma-workspace"
"/SARD-vs-CVE/CWE78_OS_CI/CVE-2019-13638~/patch"
"/SARD-vs-CVE/CWE78_OS_CI/CVE-2019-16718~/radare2"
"/SARD-vs-CVE/CWE134_FSB/CVE-2011-4930/htcondor"
"/SARD-vs-CVE/CWE134_FSB/CVE-2015-8617/php-src"
"/SARD-vs-CVE/CWE134_FSB/CVE-2017-12588/rsyslog"
"/SARD-vs-CVE/CWE400_RE/CVE-2017-11142/php-src"
"/SARD-vs-CVE/CWE400_RE/CVE-2019-12973/openjpeg"
)

for INPUT_PATH in "${INPUT_PATHS[@]}"; do
    # 홈 디렉토리 기호 처리
    INPUT_PATH="${INPUT_PATH/#\~/$HOME}"

    if [ ! -d "$INPUT_PATH" ]; then
        echo "경로가 존재하지 않음: $INPUT_PATH"
        continue
    fi

    BASENAME=$(basename "$INPUT_PATH")
    CVE_ID=$(basename "$(dirname "$INPUT_PATH")")
    TARGET_NAME="${CVE_ID}_${BASENAME}"
    DEST_DIR="data/converged/$TARGET_NAME"
    PARSED_DIR="parsed/$DEST_DIR"
    CPG_DIR="data/cpg.csv/$TARGET_NAME"

    echo "=== 처리 중: $TARGET_NAME ==="
    cd /KSignSlicer/
    mkdir -p "$DEST_DIR"
    while read -r file; do
        relpath=$(realpath --relative-to="$INPUT_PATH" "$file" | tr '/' '_')
        cp "$file" "$DEST_DIR/$relpath"
    done < <(find "$INPUT_PATH" -type f \( -name "*.c" -o -name "*.cpp" -o -name "*.h" \))

    tools/ReVeal/code-slicer/joern/joern-parse "$DEST_DIR"

    if [ -d "$PARSED_DIR" ]; then
        mkdir -p "$CPG_DIR"
        mv "$PARSED_DIR"/* "$CPG_DIR"/
        # rm "$CPG_DIR"/*.csv
    else
        echo "CPG 디렉토리 없음: $PARSED_DIR"
    fi

    rm -rf "parsed"
    echo "=== 완료: $TARGET_NAME ==="
done
