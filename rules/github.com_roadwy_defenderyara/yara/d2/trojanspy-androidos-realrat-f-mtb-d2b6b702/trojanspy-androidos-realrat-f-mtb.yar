rule TrojanSpy_AndroidOS_Realrat_F_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Realrat.F!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 05 00 00 "
		
	strings :
		$a_00_0 = {75 70 6c 6f 61 64 26 61 6e 64 72 6f 69 64 69 64 3d } 		$a_00_1 = {72 61 74 2e 70 68 70 } 		$a_00_2 = {68 69 64 65 69 63 6f 6e } 		$a_00_3 = {75 70 6c 6f 61 64 2e 70 68 70 3f } 		$a_00_4 = {75 70 6c 6f 61 64 73 6d 73 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=4
 
}