rule Rogue_Win32_PrivacyCenter_4{
	meta:
		description = "Rogue:Win32/PrivacyCenter,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 70 70 6c 79 6e 67 20 74 68 65 20 6c 61 73 74 65 73 74 } 		$a_01_1 = {66 72 6f 6d 43 68 61 72 43 6f 64 65 28 70 61 72 73 65 49 6e 74 } 		$a_01_2 = {b9 98 00 00 00 ba 40 00 00 00 } 		$a_01_3 = {b9 26 01 00 00 ba dd 01 00 00 } 		$a_01_4 = {50 72 69 76 61 63 79 20 43 65 6e 74 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}