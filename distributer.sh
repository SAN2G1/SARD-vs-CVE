#!/bin/bash


# 이동 대상 디렉토리 목록을 하드코딩
FULLPATHS=(
"/KSignSlicer/data/cpg.csv/CVE-2011-4930_htcondor"
"/KSignSlicer/data/cpg.csv/CVE-2015-8617_php-src"
"/KSignSlicer/data/cpg.csv/CVE-2017-11142_php-src"
"/KSignSlicer/data/cpg.csv/CVE-2017-12588_rsyslog"
"/KSignSlicer/data/cpg.csv/CVE-2017-15108_vd_agent"
"/KSignSlicer/data/cpg.csv/CVE-2017-15924_shadowsocks-libev"
"/KSignSlicer/data/cpg.csv/CVE-2018-16863_ghostpdl"
"/KSignSlicer/data/cpg.csv/CVE-2018-6791_plasma-workspace"
"/KSignSlicer/data/cpg.csv/CVE-2019-12973_openjpeg"
"/KSignSlicer/data/cpg.csv/CVE-2019-13638~_patch"
"/KSignSlicer/data/cpg.csv/CVE-2019-16718~_radare2"
)

BASE_DST="/SARD-vs-CVE"

for fullpath in "${FULLPATHS[@]}"; do
    [ -d "$fullpath" ] || { echo "[!] 경로 없음: $fullpath"; continue; }

    foldername=$(basename "$fullpath")  # 예: CVE-2018-16863_ghostpdl
    cve=$(echo "$foldername" | cut -d'_' -f1)       # CVE-2018-16863
    proj=$(echo "$foldername" | cut -d'_' -f2-)     # ghostpdl

    # CVE-ID에 해당하는 CWE 디렉토리 검색
    dst_base=$(find "$BASE_DST" -type d -path "*/$cve/$proj" -print -quit)

    if [ -z "$dst_base" ]; then
        echo "[!] 대상 경로 없음: $cve/$proj"
        continue
    fi

    dst_path="$dst_base/../cpg.csv"
    mkdir -p "$dst_path"
    echo "[+] 이동: $foldername → $dst_path"
    mv "$fullpath"/* "$dst_path"/
done
