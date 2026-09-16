rule Trojan_Win64_Icedid_ER_MTB_10{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 02 00 00 "
		
	strings :
		$a_00_0 = {8d 50 ff 0f af d0 f7 d2 83 ca fe 83 fa ff 0f 94 c0 41 83 f9 0a 0f 9c c1 30 c1 41 ba a1 e6 40 89 b8 e3 0e 41 e1 41 0f 45 c2 83 fa ff 0f 94 44 24 06 41 b8 e3 0e 41 e1 44 0f 45 d0 41 83 f9 0a 0f 9c 44 24 } 		$a_81_1 = {4d 67 6b 72 76 6f 69 71 6a 68 62 72 65 6f 74 62 5a 63 66 6b 77 6a 67 6a 6e 76 6a 75 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3) >=13
 
}