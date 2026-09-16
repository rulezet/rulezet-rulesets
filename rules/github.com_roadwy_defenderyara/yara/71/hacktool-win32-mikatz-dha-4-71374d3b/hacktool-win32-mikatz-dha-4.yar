rule HackTool_Win32_Mikatz_dha_4{
	meta:
		description = "HackTool:Win32/Mikatz!dha,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {62 6c 6f 67 2e 67 65 6e 74 69 6c 6b 69 77 69 2e 63 6f 6d 2f 6d 69 6d 69 6b 61 74 7a } 		$a_01_1 = {6b 65 6c 6c 6f 77 6f 72 6c 64 2e 64 6c 6c 00 68 65 6c 6c 6f 77 6f 72 6c 64 00 70 69 6e 67 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}