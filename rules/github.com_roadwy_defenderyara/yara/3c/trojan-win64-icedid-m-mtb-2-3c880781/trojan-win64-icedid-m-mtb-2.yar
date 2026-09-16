rule Trojan_Win64_IcedID_M_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {44 39 d0 0f 85 27 f9 ff ff 8b 04 24 03 04 24 ba d1 b7 ac 8d 29 c2 89 14 24 e9 12 f9 ff ff 8b 04 24 eb c2 8b 04 24 84 d2 74 32 42 8d 14 10 } 		$a_81_1 = {6b 65 70 74 79 75 } 		$a_81_2 = {6f 72 74 70 77 } 		$a_81_3 = {73 6f 72 74 79 57 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=19
 
}