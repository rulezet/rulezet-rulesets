rule Trojan_Win64_Icedid_EK_MTB_4{
	meta:
		description = "Trojan:Win64/Icedid.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 4c 6a 37 4d 46 } 		$a_01_1 = {43 62 6f 42 6a 75 33 39 } 		$a_01_2 = {48 52 68 36 46 43 51 39 31 52 72 } 		$a_01_3 = {4f 72 78 66 37 66 } 		$a_01_4 = {51 7a 59 48 35 59 50 4c 46 41 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}