name: Build C++ Application

on:
  push:
    branches: [ "main" ]
  pull_request:
    branches: [ "main" ]

jobs:
  build:
    runs-on: windows-latest

    steps:
    - name: Checkout repository
      uses: actions/checkout@v4

    - name: Compile and Embed Manifest
      run: |
        # 初始化 MSVC 编译环境
        call "C:\Program Files\Microsoft Visual Studio\2022\Enterprise\VC\Auxiliary\Build\vcvarsall.bat" x64
        
        # 步骤 1: 编译 C++ 代码生成 .exe
        cl.exe /EHsc /O2 /W3 /Fe:ForegroundBooster.exe ForegroundBooster.cpp dwmapi.lib ntdll.lib user32.lib kernel32.lib
        
        # 步骤 2: 将清单文件嵌入到 .exe 中
        mt.exe -manifest ForegroundBooster.exe.manifest -outputresource:ForegroundBooster.exe;1
      shell: cmd

    - name: Upload Artifact
      uses: actions/upload-artifact@v4
      with:
        name: ForegroundBooster
        path: ForegroundBooster.exe