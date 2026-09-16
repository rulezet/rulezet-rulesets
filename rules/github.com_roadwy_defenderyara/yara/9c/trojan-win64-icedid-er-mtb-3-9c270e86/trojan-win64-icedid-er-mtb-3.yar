rule Trojan_Win64_Icedid_ER_MTB_3{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 6c 75 67 69 6e 49 6e 69 74 } 		$a_01_1 = {51 6f 78 67 46 48 } 		$a_01_2 = {53 63 72 59 73 49 } 		$a_01_3 = {69 62 5a 49 64 4c 67 64 } 		$a_01_4 = {6c 4e 73 59 73 41 6f 70 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}