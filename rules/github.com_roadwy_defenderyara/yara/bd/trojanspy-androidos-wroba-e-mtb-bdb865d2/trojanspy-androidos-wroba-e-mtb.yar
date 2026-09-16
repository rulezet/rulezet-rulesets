rule TrojanSpy_AndroidOS_Wroba_E_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Wroba.E!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_00_0 = {42 32 33 68 62 32 37 } 		$a_00_1 = {2f 73 65 72 76 6c 65 74 2f 55 70 6c 6f 61 64 56 6f 69 63 65 } 		$a_00_2 = {2f 73 65 72 76 6c 65 74 2f 43 6f 6e 74 61 63 74 73 55 70 6c 6f 61 64 } 		$a_00_3 = {67 65 74 42 61 6e 6b 73 49 6e 66 6f } 		$a_00_4 = {34 35 30 30 36 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=5
 
}