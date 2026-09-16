rule Trojan_Win64_IcedID_MF_MTB{
	meta:
		description = "Trojan:Win64/IcedID.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 06 00 00 "
		
	strings :
		$a_01_0 = {44 6c 6c 4d 61 69 6e } 		$a_01_1 = {57 5a 53 4b 64 32 4e 45 42 49 2e 64 6c 6c } 		$a_01_2 = {46 5a 4b 6c 57 66 4e 57 4e } 		$a_01_3 = {52 50 72 57 56 42 77 } 		$a_01_4 = {6b 43 58 6b 64 4b 74 61 64 57 } 		$a_01_5 = {70 52 4e 41 55 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=15
 
}