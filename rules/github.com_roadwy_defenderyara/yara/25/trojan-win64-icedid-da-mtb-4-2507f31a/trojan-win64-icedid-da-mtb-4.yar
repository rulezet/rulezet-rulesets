rule Trojan_Win64_IcedID_DA_MTB_4{
	meta:
		description = "Trojan:Win64/IcedID.DA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,19 00 19 00 06 00 00 "
		
	strings :
		$a_00_0 = {8b 45 04 03 45 00 69 c0 ab aa aa aa 05 aa aa aa 2a 3d 55 55 55 55 72 54 } 		$a_80_1 = {6b 65 70 74 79 75 } 		$a_80_2 = {6f 72 74 70 77 } 		$a_80_3 = {73 6f 72 74 79 57 } 		$a_80_4 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_80_5 = {50 6c 75 67 69 6e 49 6e 69 74 } 	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3+(#a_80_5  & 1)*3) >=25
 
}