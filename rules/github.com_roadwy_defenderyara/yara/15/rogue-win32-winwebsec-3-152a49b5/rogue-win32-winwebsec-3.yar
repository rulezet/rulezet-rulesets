rule Rogue_Win32_Winwebsec_3{
	meta:
		description = "Rogue:Win32/Winwebsec,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 65 63 75 72 69 74 79 20 53 68 69 65 6c 64 20 } 		$a_01_1 = {53 70 79 77 61 72 65 20 66 6f 75 6e 64 20 3a } 		$a_01_2 = {50 65 61 63 6f 6d 6d 2f 44 6f 77 6e 6c 6f 61 64 65 72 } 		$a_01_3 = {76 6b 73 5f 73 63 61 6e 00 } 		$a_00_4 = {58 8d 24 94 ff e0 c3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}