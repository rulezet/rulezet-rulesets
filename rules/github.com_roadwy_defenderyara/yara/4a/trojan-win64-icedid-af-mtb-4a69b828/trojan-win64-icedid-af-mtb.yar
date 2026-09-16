rule Trojan_Win64_IcedID_AF_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 05 00 00 "
		
	strings :
		$a_80_0 = {3f 64 63 6a 69 71 70 72 40 40 59 41 48 58 5a } 		$a_80_1 = {3f 6f 77 68 79 68 64 77 77 6e 66 40 40 59 41 48 58 5a } 		$a_80_2 = {3f 76 7a 61 64 77 63 74 40 40 59 41 48 58 5a } 		$a_80_3 = {44 6c 6c 52 65 67 69 73 74 65 72 53 65 72 76 65 72 } 		$a_80_4 = {50 6c 75 67 69 6e 49 6e 69 74 } 	condition:
		((#a_80_0  & 1)*3+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=15
 
}