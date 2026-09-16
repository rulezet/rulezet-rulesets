rule Trojan_Win64_BumbleBee_EK_MTB_3{
	meta:
		description = "Trojan:Win64/BumbleBee.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6e 48 71 52 48 54 4b 56 61 65 } 		$a_01_1 = {43 72 65 61 74 65 46 69 6c 65 4d 61 70 70 69 6e 67 41 } 		$a_01_2 = {43 72 65 61 74 65 4e 61 6d 65 64 50 69 70 65 41 } 		$a_01_3 = {57 61 69 74 4e 61 6d 65 64 50 69 70 65 41 } 		$a_01_4 = {4d 61 70 56 69 65 77 4f 66 46 69 6c 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}