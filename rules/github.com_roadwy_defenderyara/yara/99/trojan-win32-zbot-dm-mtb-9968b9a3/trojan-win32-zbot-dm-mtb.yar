rule Trojan_Win32_Zbot_DM_MTB{
	meta:
		description = "Trojan:Win32/Zbot.DM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {a1 d4 f2 e0 14 85 c0 75 06 ff 15 1c f1 e0 14 8b 4c 24 08 69 c0 fd 43 03 00 2b 4c 24 04 05 c3 9e 26 00 a3 d4 f2 e0 14 41 33 d2 f7 f1 8b c2 03 44 24 04 } 		$a_00_1 = {39 45 f8 76 1d 8a c8 02 c9 a8 01 75 09 b2 f6 2a d1 00 14 38 eb 06 80 c1 07 00 0c 38 40 3b 45 f8 72 e3 } 		$a_81_2 = {6f 75 74 70 6f 73 74 2e 65 78 65 } 		$a_81_3 = {77 73 6e 70 6f 65 6d 61 2e 65 78 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=4
 
}