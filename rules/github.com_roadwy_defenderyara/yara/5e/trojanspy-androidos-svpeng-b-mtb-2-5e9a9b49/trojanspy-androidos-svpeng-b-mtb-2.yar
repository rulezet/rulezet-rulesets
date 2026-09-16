rule TrojanSpy_AndroidOS_Svpeng_B_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/Svpeng.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6b 67 66 62 6b 6e 69 6f 73 65 } 		$a_01_1 = {69 6e 6a 65 63 74 73 6c 69 73 74 } 		$a_01_2 = {64 65 66 73 6d 73 } 		$a_01_3 = {73 74 61 72 74 5f 73 6d 73 5f 67 72 61 62 } 		$a_01_4 = {62 74 74 64 6c 72 76 61 76 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}