rule Rogue_Win32_InternetAntivirus_4{
	meta:
		description = "Rogue:Win32/InternetAntivirus,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 74 6f 70 20 22 49 54 47 72 64 45 6e 67 69 6e 65 22 } 		$a_01_1 = {2f 75 6e 69 6e 73 74 61 6c 6c 20 2f 73 69 6c 65 6e 74 00 } 		$a_01_2 = {44 65 6c 65 74 69 6e 67 20 73 65 74 74 69 6e 67 73 20 69 6e 69 20 66 69 6c 65 3a 20 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}