rule TrojanSpy_AndroidOS_FakeBank_C_MTB_2{
	meta:
		description = "TrojanSpy:AndroidOS/FakeBank.C!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {44 65 41 64 6d 69 6e 52 65 63 69 76 65 72 } 		$a_01_1 = {2f 61 70 70 48 6f 6d 65 2f 73 65 72 76 6c 65 74 2f 55 70 6c 6f 61 64 49 6d 61 67 65 } 		$a_01_2 = {67 65 74 42 61 6e 6b 53 68 6f 72 74 42 79 70 61 63 6b } 		$a_01_3 = {67 65 74 42 61 6e 6b 73 49 6e 66 6f } 		$a_01_4 = {67 65 74 49 6e 73 74 61 6c 6c 65 64 50 61 63 6b 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}