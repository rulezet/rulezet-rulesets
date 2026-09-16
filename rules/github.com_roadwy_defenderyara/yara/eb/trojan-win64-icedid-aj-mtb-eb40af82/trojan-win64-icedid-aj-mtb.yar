rule Trojan_Win64_IcedID_AJ_MTB{
	meta:
		description = "Trojan:Win64/IcedID.AJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 63 56 6e 65 56 68 48 6c 65 7a } 		$a_01_1 = {41 6a 77 54 4a 66 4a 75 } 		$a_01_2 = {44 61 45 6d 4b 62 43 } 		$a_01_3 = {44 66 55 4b 79 45 74 65 53 } 		$a_01_4 = {50 6c 75 67 69 6e 49 6e 69 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}