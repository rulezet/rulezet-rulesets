rule TrojanSpy_AndroidOS_SmForw_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmForw.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {53 65 6e 64 50 6f 6b 65 } 		$a_00_1 = {67 65 74 54 65 6c 43 6f 6d 70 61 6e 79 } 		$a_00_2 = {68 70 5f 67 65 74 73 6d 73 62 6c 6f 63 6b 73 74 61 74 65 2e 70 68 70 3f 74 65 6c 6e 75 6d } 		$a_00_3 = {69 6e 64 65 78 2e 70 68 70 3f 74 79 70 65 3d 72 65 63 65 69 76 65 73 6d 73 26 74 65 6c 6e 75 6d } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}