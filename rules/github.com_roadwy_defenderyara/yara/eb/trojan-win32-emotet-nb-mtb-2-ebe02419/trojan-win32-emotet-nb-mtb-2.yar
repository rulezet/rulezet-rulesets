rule Trojan_Win32_Emotet_NB_MTB_2{
	meta:
		description = "Trojan:Win32/Emotet.NB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_00_0 = {8b c7 0f af c7 89 44 24 10 8d 54 2d 00 2b c2 89 54 24 24 8d 14 41 a1 60 11 0d 10 8d 48 02 0f af c8 2b d1 03 54 24 10 8d 04 5b 03 c0 b9 06 00 00 00 2b c8 0f af cb 8d } 		$a_81_1 = {45 6d 6f 74 69 6f 6e 53 65 6c 44 65 6d 6f } 		$a_81_2 = {68 6f 6f 64 6c 75 6d 31 39 38 30 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3) >=16
 
}