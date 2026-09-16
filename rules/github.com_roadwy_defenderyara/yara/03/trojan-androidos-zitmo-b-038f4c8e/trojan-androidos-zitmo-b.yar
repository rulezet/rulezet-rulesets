rule Trojan_AndroidOS_Zitmo_B{
	meta:
		description = "Trojan:AndroidOS/Zitmo.B,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {26 66 72 6f 6d 3d 25 73 26 74 65 78 74 3d 25 73 } 		$a_01_1 = {3f 74 6f 3d 25 73 26 69 3d 25 73 26 6d 3d 25 73 } 		$a_01_2 = {26 66 3d 31 } 		$a_01_3 = {46 69 72 73 74 52 75 6e } 		$a_01_4 = {46 69 72 65 47 65 74 52 65 71 75 65 73 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}