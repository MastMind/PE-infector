@ECHO OFF

set BUILD_DIR=build
set CXXFLAGS=-Wall -c -I. -static
set LDFLAGS=-L. -static -m32
set PROGNAME=PE-infector
rd /S /Q %BUILD_DIR%
mkdir %BUILD_DIR%

for /R %%f in (*.c) do (
	gcc %CXXFLAGS% %%f -o %BUILD_DIR%/%%~nf.o
	if NOT ERRORLEVEL 1 (set compiled="success")
)

if DEFINED compiled (
	gcc -o %BUILD_DIR%/%PROGNAME%.exe %BUILD_DIR%/*.o %LDFLAGS%
	if NOT ERRORLEVEL 1 (@echo "Compilation success") else (@echo "Linking failed!")
) else (@echo "Compilation failed!")