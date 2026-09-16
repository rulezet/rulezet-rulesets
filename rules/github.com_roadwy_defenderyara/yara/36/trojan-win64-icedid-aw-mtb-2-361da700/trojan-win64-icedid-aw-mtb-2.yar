rule Trojan_Win64_IcedID_AW_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,13 00 13 00 04 00 00 "
		
	strings :
		$a_00_0 = {48 89 c3 48 83 eb 05 b9 08 c1 44 00 48 29 cb 50 b8 d7 0d 2c 00 48 01 d8 83 38 00 74 03 } 		$a_81_1 = {73 61 64 6c 5f 36 34 2e 64 6c 6c } 		$a_81_2 = {47 65 74 4d 6f 64 75 6c 65 48 61 6e 64 6c 65 41 } 		$a_81_3 = {53 48 47 65 74 46 6f 6c 64 65 72 50 61 74 68 41 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3+(#a_81_3  & 1)*3) >=19
 
}