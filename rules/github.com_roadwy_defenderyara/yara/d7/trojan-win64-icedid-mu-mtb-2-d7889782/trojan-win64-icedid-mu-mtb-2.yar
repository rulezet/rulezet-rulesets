rule Trojan_Win64_IcedID_MU_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.MU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {52 75 6e 4f 62 6a 65 63 74 } 		$a_01_1 = {51 53 30 37 4a 63 2e 64 6c 6c } 		$a_01_2 = {41 48 70 4f 77 4a 77 64 62 } 		$a_01_3 = {42 53 4b 4b 58 4b 68 57 41 65 } 		$a_01_4 = {44 47 43 6d 6f 4c 52 61 56 68 59 } 		$a_01_5 = {57 6e 4f 72 5a 73 61 78 47 41 6e } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}