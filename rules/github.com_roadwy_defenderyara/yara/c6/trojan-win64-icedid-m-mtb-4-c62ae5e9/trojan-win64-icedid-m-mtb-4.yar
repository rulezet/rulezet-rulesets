rule Trojan_Win64_IcedID_M_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 8b 75 e8 48 89 75 b0 48 8b 7d e0 4c 8b 75 d8 48 b9 ff ff ff ff ff ff ff 3f 48 85 ff 74 03 44 89 3f 48 83 c7 04 48 89 7d e0 41 ff c7 44 89 7d d0 41 83 ff 05 7d 1f } 		$a_81_1 = {61 62 67 6d 77 65 6c 6d 6a 73 6e 6f 6d 69 63 64 } 		$a_81_2 = {45 6e 74 72 79 50 6f 69 6e 74 31 } 		$a_81_3 = {62 61 6c 6b 7a 71 73 7a } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=19
 
}