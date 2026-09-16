rule Trojan_Win64_Icedid_ER_MTB_5{
	meta:
		description = "Trojan:Win64/Icedid.ER!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 76 6e 4d 69 46 64 52 59 6d } 		$a_01_1 = {42 6e 79 69 75 74 74 32 37 } 		$a_01_2 = {45 74 32 77 38 47 41 69 75 78 } 		$a_01_3 = {45 7a 78 64 30 50 7a 33 } 		$a_01_4 = {4b 4b 4e 78 41 50 66 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}