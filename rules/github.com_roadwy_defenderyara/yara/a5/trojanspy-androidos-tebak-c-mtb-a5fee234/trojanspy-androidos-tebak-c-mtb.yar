rule TrojanSpy_AndroidOS_Tebak_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Tebak.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 6e 66 6f 47 65 74 74 65 72 } 		$a_01_1 = {62 61 6e 6b 6e 75 6d 70 77 } 		$a_01_2 = {2f 75 70 6c 6f 61 64 2e 70 68 70 } 		$a_01_3 = {2f 73 65 6e 64 5f 62 61 6e 6b 2e 70 68 70 } 		$a_01_4 = {73 65 6e 64 5f 73 69 6d 5f 6e 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}