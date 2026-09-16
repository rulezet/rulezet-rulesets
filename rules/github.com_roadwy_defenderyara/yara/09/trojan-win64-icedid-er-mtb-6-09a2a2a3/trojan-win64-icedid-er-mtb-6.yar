rule Trojan_Win64_Icedid_ER_MTB_6{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 51 61 69 58 31 33 63 46 46 6c } 		$a_01_1 = {54 7a 39 75 46 41 62 65 } 		$a_01_2 = {58 36 6a 76 75 63 36 4a 5a 72 } 		$a_01_3 = {58 77 33 53 5a 75 45 4d 58 } 		$a_01_4 = {68 59 70 37 6f 79 49 49 67 43 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}