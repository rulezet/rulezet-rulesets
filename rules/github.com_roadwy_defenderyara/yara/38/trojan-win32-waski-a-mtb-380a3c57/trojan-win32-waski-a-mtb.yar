rule Trojan_Win32_Waski_A_MTB{
	meta:
		description = "Trojan:Win32/Waski.A!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {b8 77 07 00 00 57 50 ba 24 24 40 00 52 ff 15 } 		$a_00_1 = {4f 66 8b 07 8a cc 47 33 c0 e8 de 01 00 00 } 		$a_02_2 = {8b 06 33 c1 e8 0b 00 00 00 c3 [0-15] 8b c8 88 07 83 c6 01 c3 } 		$a_00_3 = {6a 00 68 ff 00 00 00 68 00 da 55 00 68 18 21 55 00 68 18 21 55 00 6a 00 ff 15 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}