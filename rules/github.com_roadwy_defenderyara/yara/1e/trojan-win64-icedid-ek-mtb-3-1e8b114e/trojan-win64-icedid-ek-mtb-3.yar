rule Trojan_Win64_Icedid_EK_MTB_3{
	meta:
		description = "Trojan:Win64/Icedid.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 4f 46 50 70 6b 33 } 		$a_01_1 = {4a 55 36 64 54 67 6c } 		$a_01_2 = {4d 49 51 6a 58 4b 5a } 		$a_01_3 = {4d 75 7a 4f 4b 79 41 } 		$a_01_4 = {54 36 61 31 6d 6b 54 72 49 53 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}