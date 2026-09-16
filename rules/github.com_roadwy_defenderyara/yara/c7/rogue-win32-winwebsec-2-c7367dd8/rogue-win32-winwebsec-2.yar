rule Rogue_Win32_Winwebsec_2{
	meta:
		description = "Rogue:Win32/Winwebsec,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2f 61 76 2e 65 78 65 } 		$a_01_1 = {73 65 5c 44 6f 77 6e 6c 6f 61 64 65 72 53 68 65 6c 6c 63 6f 64 65 2e 70 64 62 } 		$a_01_2 = {5c 54 65 6d 70 6f 72 61 72 79 20 49 6e 74 65 72 6e 65 74 20 46 69 6c 65 73 5c 63 6f 6b 70 65 2e 65 78 65 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}