rule Trojan_Win64_IcedID_DC_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,1a 00 1a 00 04 00 00 "
		
	strings :
		$a_00_0 = {69 48 28 fd 43 03 00 81 c1 c3 9e 26 00 89 48 28 c1 e9 10 81 e1 ff 7f 00 00 8b c1 48 83 c4 28 c3 } 		$a_00_1 = {48 8d 54 24 41 0f 28 05 bc 81 05 00 0f 29 42 ff c7 42 0f ff e7 e1 f7 c6 42 13 00 b8 01 } 		$a_80_2 = {52 74 6c 4c 6f 6f 6b 75 70 46 75 6e 63 74 69 6f 6e 45 6e 74 72 79 } 		$a_80_3 = {54 72 61 6e 73 6c 61 74 65 41 63 63 65 6c 65 72 61 74 6f 72 57 } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*10+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3) >=26
 
}