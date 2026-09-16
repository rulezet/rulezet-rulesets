rule TrojanSpy_AndroidOS_SAgnt_AD_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.AD!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {75 70 44 65 76 69 63 65 49 6e 66 6f } 		$a_01_1 = {4c 63 6f 6d 2f 63 61 66 65 32 34 2f 68 6f 73 74 73 } 		$a_01_2 = {67 65 74 5f 73 6d 73 5f 69 6e 66 6f } 		$a_01_3 = {75 70 43 6f 6e 74 61 63 74 73 } 		$a_01_4 = {53 4d 53 5f 41 5f 55 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}