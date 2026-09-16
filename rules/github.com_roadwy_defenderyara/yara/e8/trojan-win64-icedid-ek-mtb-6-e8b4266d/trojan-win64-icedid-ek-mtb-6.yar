rule Trojan_Win64_Icedid_EK_MTB_6{
	meta:
		description = "Trojan:Win64/Icedid.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 74 48 63 72 58 61 79 73 71 57 75 76 6f 4b } 		$a_01_1 = {49 6d 76 62 7a 43 54 45 57 48 78 7a 68 4b 57 4e } 		$a_01_2 = {4a 4f 62 62 70 44 42 44 76 45 44 4c 6c } 		$a_01_3 = {4e 6b 44 57 62 70 75 70 6c 44 72 51 53 4f } 		$a_01_4 = {50 6c 75 67 69 6e 49 6e 69 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}