rule TrojanSpy_AndroidOS_Banker_I_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.I!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {61 70 69 2e 62 61 6e 61 6e 61 73 70 6c 69 74 2e 73 68 6f 70 } 		$a_00_1 = {63 6f 6d 2f 6b 69 74 6b 61 67 61 6d 65 73 2f 66 61 6c 6c 62 75 64 64 69 65 73 } 		$a_00_2 = {68 61 73 53 6d 73 53 65 72 76 69 63 65 73 } 		$a_00_3 = {6d 6f 62 69 6c 65 4e 75 6d 62 65 72 50 6f 72 74 61 62 6c 65 52 65 67 69 6f 6e 5f } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1) >=4
 
}