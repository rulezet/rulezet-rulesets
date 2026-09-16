rule TrojanSpy_AndroidOS_SAgnt_D_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {63 6f 6e 74 61 63 74 73 2e 6a 73 6f 6e } 		$a_00_1 = {73 6d 73 2e 6a 73 6f 6e } 		$a_00_2 = {67 65 74 43 61 6c 6c 73 4c 6f 67 73 } 		$a_00_3 = {67 65 74 53 4d 53 } 		$a_00_4 = {67 65 74 43 6f 6e 74 61 63 74 73 } 		$a_00_5 = {4c 63 6f 6d 2f 63 72 2f 63 68 61 74 2f 61 63 74 69 76 69 74 69 65 73 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}