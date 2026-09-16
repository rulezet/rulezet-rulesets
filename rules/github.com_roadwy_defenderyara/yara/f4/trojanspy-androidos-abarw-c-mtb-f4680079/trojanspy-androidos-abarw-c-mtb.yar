rule TrojanSpy_AndroidOS_Abarw_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Abarw.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {41 72 61 62 57 61 72 65 53 4d 53 } 		$a_01_1 = {74 69 6d 65 72 5f 61 74 74 61 63 6b } 		$a_01_2 = {64 72 6f 69 64 2f 63 68 69 6c 64 2f 4d 61 69 6e 41 63 74 69 76 69 74 79 } 		$a_01_3 = {5f 73 65 6e 64 5f 54 65 6c 67 72 61 } 		$a_01_4 = {5f 73 74 61 72 74 5f 61 74 74 61 63 6b } 		$a_01_5 = {5f 67 6f 74 65 6c 67 72 61 6d 5f 72 65 71 75 65 73 74 5f 6c 69 73 74 65 6e 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}