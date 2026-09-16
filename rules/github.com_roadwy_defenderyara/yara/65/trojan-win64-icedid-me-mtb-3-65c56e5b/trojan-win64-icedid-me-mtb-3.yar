rule Trojan_Win64_IcedID_ME_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 8b c6 48 2b c7 48 c1 f8 02 48 83 f8 01 73 5e 49 2b fe 48 c1 ff 02 48 8b c1 48 2b c7 48 83 f8 01 72 7a 48 8d 57 01 49 2b f6 48 c1 fe 02 48 8b c6 48 d1 e8 48 2b c8 } 		$a_81_1 = {63 73 62 75 71 79 61 73 6e } 		$a_81_2 = {63 77 6c 76 71 70 71 70 69 63 64 64 66 70 } 		$a_81_3 = {64 7a 78 76 65 72 76 65 64 67 79 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=19
 
}