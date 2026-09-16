rule TrojanSpy_AndroidOS_Svpeng_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Svpeng.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 65 43 2f 76 42 71 69 78 2f 66 42 71 4f 75 68 2f 70 71 79 64 51 73 6a 79 6c 79 6a 4f } 		$a_01_1 = {4e 6f 4e 65 4e 6f 4e 65 } 		$a_01_2 = {73 6d 73 67 72 61 62 } 		$a_01_3 = {73 74 61 72 74 5f 73 6d 73 5f 67 72 61 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}