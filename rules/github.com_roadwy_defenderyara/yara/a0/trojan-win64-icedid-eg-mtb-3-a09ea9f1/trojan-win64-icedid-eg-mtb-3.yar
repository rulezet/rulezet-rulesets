rule Trojan_Win64_IcedID_EG_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.EG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {44 89 4c 24 20 4c 89 44 24 18 3a e4 74 d6 b8 4d 00 00 00 83 c0 18 66 3b d2 74 00 66 89 44 24 52 b8 45 00 00 00 66 3b d2 74 35 } 		$a_01_1 = {75 69 73 62 61 64 79 75 67 61 75 73 62 64 6a 61 73 79 75 64 6a 61 73 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*1) >=4
 
}