@echo off
setlocal
pushd "%~dp0"

REM ============================================================
REM  Variable-name style toggle:
REM    CUSTOM  = use the seed words in names.txt (waffles1, etc.)
REM    DEFAULT = use short 1-2 char names (a, aa, ab, ...)
REM ============================================================
set "NAME_STYLE=DEFAULT"

if not exist "input.lua" (
    echo Error: input.lua not found in %CD%
    popd
    exit /b 1
)

if /i "%NAME_STYLE%"=="CUSTOM" (
    if not exist "names.txt" (
        echo Error: NAME_STYLE=CUSTOM but names.txt not found in %CD%
        popd
        exit /b 1
    )
    echo [Wabi Sabi] Using CUSTOM names from names.txt
    set "NAME_ARGS=--names names.txt"
) else (
    echo [Wabi Sabi] Using DEFAULT 1-2 char names
    set "NAME_ARGS=--no-names"
)

cargo run --release --quiet -p wabisabi-cli -- compile "input.lua" -o "output.lua" %NAME_ARGS%
set "EXIT_CODE=%ERRORLEVEL%"

popd
exit /b %EXIT_CODE%
