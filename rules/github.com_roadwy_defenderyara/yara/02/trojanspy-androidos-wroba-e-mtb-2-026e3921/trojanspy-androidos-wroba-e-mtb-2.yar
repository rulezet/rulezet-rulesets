rule TrojanSpy_AndroidOS_Wroba_E_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/Wroba.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {73 6d 73 20 4c 6f 63 6b } 		$a_01_1 = {73 74 6f 70 20 66 6f 72 77 61 72 64 } 		$a_01_2 = {5f 4f 74 70 5f 50 73 77 } 		$a_01_3 = {5f 43 61 72 64 5f 50 73 77 } 		$a_01_4 = {26 73 65 6e 64 6f 75 74 4f 72 49 6e 3d } 		$a_01_5 = {65 78 65 63 75 74 65 20 63 6f 6d 6d 61 6e 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}