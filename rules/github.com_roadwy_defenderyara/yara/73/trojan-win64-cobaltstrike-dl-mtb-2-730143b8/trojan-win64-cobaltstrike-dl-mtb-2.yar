rule Trojan_Win64_Cobaltstrike_DL_MTB_2{
	meta:
		description = "Trojan:Win64/Cobaltstrike.DL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,12 00 12 00 03 00 00 "
		
	strings :
		$a_00_0 = {50 c7 44 24 04 00 00 00 00 b8 90 5f 01 00 48 03 05 da 2f 00 00 41 5a 48 ff e0 } 		$a_00_1 = {33 65 33 6d 31 6c 30 65 30 65 30 67 30 68 30 69 30 66 30 6b 30 6c 30 6d 30 6e 30 6f 30 70 30 71 30 72 31 63 31 64 31 } 		$a_80_2 = {52 65 74 70 6f 6c 69 6e 65 } 	condition:
		((#a_00_0  & 1)*10+(#a_00_1  & 1)*5+(#a_80_2  & 1)*3) >=18
 
}