# PE-infector
Crossplatform tool for injecting shellcode into .exe or .dll binaries (x86 and 64).

## Build:

	Linux:
		Run make in directory
	
	Windows:
		Run compile.bat

## Usage:

1. Prepare the shellcode (for example build raw shellcode with metasploit framework to file; recommend with option EXITFUNC=none if it possible for resume execution of original program)
2. Run PE-infector -i <path_for_source_exe_or_dll> -o <patched_exe_or_dll> -s <path_for_shellcode>
	Support x86 and x64 .exe/.dll binaries. 
	Also support injection methods:
	
		1. Code injection (default method; success if enough empty space)
		2. Create new section (turn on with option -m sect; by default section name has value ".code"; use additional option -n for set custom section name)
		3. Resize current code section (turn on with option -m resz)
		
	Also support output for current sections (option -d)
	
	Also support run shellcode in another thread (option -t or --thread. For 32bit only)

## Example:

For Kali Linux instruction (it doesn't matter which distributive use; it is just convinient to use Kali linux cause it has preinstalled metasploit framework for generating shellcodes).

1. Generate the shellcode with effect show the window with caption:

		msfvenom -p windows/messagebox TEXT="Big brother watches you." -f raw > shellcode.raw

2. Inject generated raw file into exe (choosen method resz cause it works in the most cases):

		PE-infector -i original.exe -o injected.exe -s shellcode.raw -m resz

3. In success injected.exe will be generated
4. Profit!

