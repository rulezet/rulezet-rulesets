rule TrojanSpy_AndroidOS_Banker_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Banker.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,07 00 07 00 05 00 00 "
		
	strings :
		$a_00_0 = {41 6e 64 72 6f 69 64 42 6f 74 2f 53 63 72 65 65 6e 63 61 73 74 } 		$a_00_1 = {61 6e 64 72 6f 69 64 3a 69 64 2f 73 6d 73 5f 73 68 6f 72 74 5f 63 6f 64 65 5f 72 65 6d 65 6d 62 65 72 5f 63 68 6f 69 63 65 5f 63 68 65 63 6b 62 6f 78 } 		$a_00_2 = {74 74 39 2e 70 61 67 65 2e 6c 69 6e 6b 2f 58 6b 74 53 } 		$a_00_3 = {49 6e 6a 65 63 74 43 6f 6d 70 6f 6e 65 6e 74 } 		$a_00_4 = {72 65 71 75 65 73 74 5f 63 72 65 64 65 6e 74 69 61 6c 73 } 	condition:
		((#a_00_0  & 1)*3+(#a_00_1  & 1)*3+(#a_00_2  & 1)*1+(#a_00_3  & 1)*1+(#a_00_4  & 1)*1) >=7
 
}