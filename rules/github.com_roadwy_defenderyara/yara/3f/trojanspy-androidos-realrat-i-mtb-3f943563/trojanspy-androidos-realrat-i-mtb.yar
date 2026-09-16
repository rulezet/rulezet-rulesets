rule TrojanSpy_AndroidOS_Realrat_I_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Realrat.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {68 69 64 65 73 65 72 76 69 63 65 5f 42 52 } 		$a_01_1 = {67 65 74 41 6c 6c 43 6f 6e 74 61 63 74 73 } 		$a_01_2 = {43 6f 6e 74 61 63 74 73 32 57 72 61 70 70 65 72 } 		$a_01_3 = {67 65 74 41 6c 6c 43 61 6c 6c 73 } 		$a_01_4 = {53 6d 73 57 72 61 70 70 65 72 } 		$a_01_5 = {66 61 6b 65 6d 61 69 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}