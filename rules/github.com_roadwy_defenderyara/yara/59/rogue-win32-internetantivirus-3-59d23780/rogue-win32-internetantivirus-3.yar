rule Rogue_Win32_InternetAntivirus_3{
	meta:
		description = "Rogue:Win32/InternetAntivirus,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 04 00 00 "
		
	strings :
		$a_00_0 = {67 65 6e 61 76 69 72 2e 65 78 65 00 6c 69 76 65 65 73 2e 65 78 65 00 } 		$a_00_1 = {69 61 76 69 72 2e 65 78 65 00 } 		$a_01_2 = {50 72 6f 63 42 6c 6f 63 6b 00 } 		$a_01_3 = {50 72 6f 63 65 73 73 42 6c 6f 63 6b 00 } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=21
 
}