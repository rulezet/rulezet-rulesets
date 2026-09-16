rule Trojan_Win64_IcedID_BM_MTB{
	meta:
		description = "Trojan:Win64/IcedID.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {43 36 4c 32 73 4a 4b } 		$a_01_1 = {46 56 69 36 68 31 } 		$a_01_2 = {52 75 6e 4f 62 6a 65 63 74 } 		$a_01_3 = {5a 36 35 50 64 53 74 } 		$a_01_4 = {61 36 57 44 48 72 66 73 61 36 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}