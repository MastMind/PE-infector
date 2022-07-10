# PE-infector
Crossplatform tool for inject shellcode into .exe binaries (x86 and 64).

Build:

	Linux:
		Run make in directory
	
	Windows:
		Run compile.bat

Usage:

1. Prepare the shellcode (for example build raw shellcode with metasploit framework to file; recommend with option EXITFUNC=none if it possible for resume execution of original program)
2. Run PE-infector -i <path_for_source_exe> -o <patched_exe> -s <path_for_shellcode>
	Support x86 and x64 .exe binaries. 
	Also support injection methods:
	
		1. Code injection (default method; success if enough empty space)
		2. Create new section (turn on with option -m sect)
		3. Resize current code section (turn on with option -m resz)
		
	Also support output for current sections (option -d)
