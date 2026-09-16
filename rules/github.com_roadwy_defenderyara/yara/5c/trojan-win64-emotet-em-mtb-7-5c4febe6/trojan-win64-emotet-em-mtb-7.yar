rule Trojan_Win64_Emotet_EM_MTB_7{
	meta:
		description = "Trojan:Win64/Emotet.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {79 7a 6b 45 4e 54 6d 42 56 } 		$a_01_1 = {7a 51 6e 46 6b 45 73 67 6c 76 53 6d 59 74 4b 6c 6b 46 44 54 6d 65 } 		$a_01_2 = {7a 64 4d 68 59 77 } 		$a_01_3 = {4f 75 74 70 75 74 44 65 62 75 67 53 74 72 69 6e 67 57 } 		$a_01_4 = {43 72 65 61 74 65 46 69 6c 65 57 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}