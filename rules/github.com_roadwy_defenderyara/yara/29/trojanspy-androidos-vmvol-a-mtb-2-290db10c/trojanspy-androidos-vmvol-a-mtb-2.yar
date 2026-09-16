rule TrojanSpy_AndroidOS_Vmvol_A_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/Vmvol.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {2f 75 70 6c 6f 61 64 53 6d 73 2e 68 74 6d } 		$a_00_1 = {2f 75 70 6c 6f 61 64 41 6c 62 75 6d 2e 68 74 6d } 		$a_00_2 = {2f 75 70 6c 6f 61 64 43 6f 6e 74 61 63 74 2e 68 74 6d } 		$a_00_3 = {2f 41 75 74 6f 52 75 6e 52 65 63 65 69 76 65 72 3b } 		$a_00_4 = {69 73 55 70 6c 6f 61 64 45 6e 76 69 72 6f 6e 6d 65 6e 74 52 65 63 6f 72 64 } 		$a_00_5 = {73 65 74 55 70 6c 6f 61 64 43 61 6c 6c 6c 6f 67 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1+(#a_00_5  & 1)*1) >=5
 
}