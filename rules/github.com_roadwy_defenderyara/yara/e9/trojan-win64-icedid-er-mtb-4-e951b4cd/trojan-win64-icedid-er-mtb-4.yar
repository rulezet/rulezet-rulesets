rule Trojan_Win64_Icedid_ER_MTB_4{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {48 79 75 61 73 62 62 6a 68 61 73 } 		$a_01_1 = {53 36 43 53 66 66 39 } 		$a_01_2 = {5a 31 61 30 6f 59 53 6d 36 } 		$a_01_3 = {65 45 72 61 6e 76 70 } 		$a_01_4 = {71 46 59 62 75 4c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}