rule Trojan_Win64_IcedID_M_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {49 2b fe 48 c1 ff 02 48 8b c1 48 2b c7 48 83 f8 01 72 7a 48 8d 57 01 49 2b f6 48 c1 fe 02 48 8b c6 48 d1 e8 48 2b c8 48 03 c6 4d 8b c4 48 3b ce 4c 0f 43 c0 4c 3b c2 49 0f 43 d0 48 8d 4d d8 } 		$a_81_1 = {61 69 76 6f 75 6f 71 } 		$a_81_2 = {61 72 6d 6d 67 79 62 } 		$a_81_3 = {45 6e 74 72 79 46 75 6e 63 74 31 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=19
 
}