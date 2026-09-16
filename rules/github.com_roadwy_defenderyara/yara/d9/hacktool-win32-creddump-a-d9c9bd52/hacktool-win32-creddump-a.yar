rule HackTool_Win32_CredDump_A{
	meta:
		description = "HackTool:Win32/CredDump.A,SIGNATURE_TYPE_PEHSTR,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {5c 63 72 65 64 2e 74 78 74 } 		$a_01_1 = {5c 63 72 65 64 64 75 6d 70 2e 64 6c 6c } 		$a_01_2 = {43 72 65 64 65 6e 74 69 61 6c 20 53 65 74 3a 20 45 6e 74 65 72 70 72 69 73 65 } 		$a_01_3 = {25 73 5c 4d 69 63 72 6f 73 6f 66 74 5c 43 72 65 64 65 6e 74 69 61 6c 73 5c 25 73 5c 63 72 65 64 65 6e 74 69 61 6c 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}