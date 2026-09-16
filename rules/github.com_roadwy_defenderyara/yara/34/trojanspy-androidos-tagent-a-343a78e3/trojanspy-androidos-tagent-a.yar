rule TrojanSpy_AndroidOS_Tagent_A{
	meta:
		description = "TrojanSpy:AndroidOS/Tagent.A,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {65 72 72 6f 72 57 68 65 72 65 } 		$a_01_1 = {65 76 65 72 79 6f 6e 65 2e 65 76 6c } 		$a_01_2 = {63 61 6c 6c 20 72 65 63 20 73 74 61 74 75 73 20 69 73 } 		$a_01_3 = {52 65 63 6f 72 64 73 20 4c 6f 67 20 65 76 65 72 79 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}