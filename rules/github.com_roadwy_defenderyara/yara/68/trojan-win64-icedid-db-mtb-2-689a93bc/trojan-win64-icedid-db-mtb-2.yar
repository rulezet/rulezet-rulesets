rule Trojan_Win64_IcedID_DB_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 "
		
	strings :
		$a_00_0 = {48 c1 eb 20 01 c3 81 c3 eb 14 00 00 89 df c1 ef 1f c1 fb 06 01 fb 89 df c1 e7 07 29 fb 8d 3c 03 81 c7 eb 14 00 00 01 d8 05 6a 15 } 		$a_80_1 = {67 6c 6f 65 71 77 } 		$a_80_2 = {67 77 78 62 6f 70 77 } 		$a_80_3 = {6a 6c 78 6e 65 77 } 		$a_80_4 = {4b 69 6c 6c 54 69 6d 65 72 } 		$a_80_5 = {53 65 6e 64 4d 65 73 73 61 67 65 57 } 	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=25
 
}