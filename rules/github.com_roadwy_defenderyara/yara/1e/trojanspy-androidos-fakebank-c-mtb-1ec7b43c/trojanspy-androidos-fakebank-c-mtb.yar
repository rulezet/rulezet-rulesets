rule TrojanSpy_AndroidOS_FakeBank_C_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/FakeBank.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,0a 00 0a 00 07 00 00 "
		
	strings :
		$a_01_0 = {61 70 70 2e 72 65 61 64 63 6f 6e 74 61 63 74 73 } 		$a_01_1 = {67 65 74 41 6c 6c 53 6d 73 } 		$a_01_2 = {73 79 6e 63 4d 65 73 73 } 		$a_01_3 = {67 65 74 5f 61 64 64 72 65 73 73 } 		$a_01_4 = {67 65 74 5f 66 6f 6c 64 65 72 4e 61 6d 65 } 		$a_01_5 = {63 61 72 64 4e 6f 45 74 } 		$a_01_6 = {63 63 76 45 74 } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=10
 
}