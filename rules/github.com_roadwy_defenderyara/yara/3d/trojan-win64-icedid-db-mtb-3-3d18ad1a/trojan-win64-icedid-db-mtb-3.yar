rule Trojan_Win64_IcedID_DB_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {81 f9 9a d5 c9 bf 7e 2d 81 f9 bc 8b 54 f8 7e 60 81 f9 bd 8b 54 f8 0f 84 bb 00 00 00 81 f9 d6 b0 5b f8 0f 84 a9 00 00 00 81 f9 80 b1 1c 78 75 d0 e9 fd } 		$a_80_1 = {63 72 31 2e 64 6c 6c } 		$a_80_2 = {53 79 73 74 65 6d 50 61 72 61 6d 65 74 65 72 73 49 6e 66 6f 41 } 		$a_80_3 = {53 65 6e 64 4d 65 73 73 61 67 65 41 } 		$a_80_4 = {47 65 74 43 6c 61 73 73 4e 61 6d 65 41 } 	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}