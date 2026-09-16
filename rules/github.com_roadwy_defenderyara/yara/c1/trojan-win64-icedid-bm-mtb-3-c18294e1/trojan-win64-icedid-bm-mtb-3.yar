rule Trojan_Win64_IcedID_BM_MTB_3{
	meta:
		description = "Trojan:Win64/IcedID.BM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 50 6d 7a 44 42 4c 71 42 76 } 		$a_01_1 = {42 79 73 41 62 39 67 52 4f 48 } 		$a_01_2 = {49 42 70 6c 76 36 } 		$a_01_3 = {50 6c 75 67 69 6e 49 6e 69 74 } 		$a_01_4 = {51 36 79 59 51 45 76 68 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}