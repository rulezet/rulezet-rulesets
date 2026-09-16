rule Trojan_Win64_IcedID_BM_MTB_2{
	meta:
		description = "Trojan:Win64/IcedID.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 79 6b 49 72 78 6c 57 67 53 } 		$a_01_1 = {49 39 51 57 46 34 45 } 		$a_01_2 = {4d 34 59 50 44 51 6e } 		$a_01_3 = {50 67 5a 74 55 49 77 4c 32 39 } 		$a_01_4 = {50 6e 33 5a 5a 68 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}