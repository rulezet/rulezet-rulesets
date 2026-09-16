rule Trojan_Win32_Emotet_M_MTB{
	meta:
		description = "Trojan:Win32/Emotet.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {f7 e9 03 d1 8b 8c fe 14 07 00 00 c1 fa 0e 8b c2 c1 e8 1f 03 c2 4b 8b ac c6 14 07 00 00 8b 94 fe 18 07 00 00 89 ac fe 14 07 } 		$a_81_1 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_81_2 = {68 61 31 6d 65 35 69 } 		$a_81_3 = {74 62 62 49 37 72 32 37 64 63 6c 32 4d } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=19
 
}