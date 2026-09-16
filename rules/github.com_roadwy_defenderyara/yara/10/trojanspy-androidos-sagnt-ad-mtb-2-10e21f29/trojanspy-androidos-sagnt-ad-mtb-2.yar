rule TrojanSpy_AndroidOS_SAgnt_AD_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.AD!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_00_0 = {79 6f 75 72 2d 61 70 70 2e 78 79 7a 2f 68 69 72 6f } 		$a_00_1 = {73 70 2e 6f 72 67 2e 68 74 74 70 75 74 69 6c 73 32 73 65 72 76 69 63 65 } 		$a_00_2 = {73 70 2e 6f 72 67 2e 68 74 74 70 6a 6f 62 } 		$a_00_3 = {73 70 2e 6f 72 67 2e 70 6e 73 65 72 76 69 63 65 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}