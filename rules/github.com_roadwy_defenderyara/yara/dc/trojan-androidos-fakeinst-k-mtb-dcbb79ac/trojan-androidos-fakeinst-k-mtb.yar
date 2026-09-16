rule Trojan_AndroidOS_FakeInst_K_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {6a 6f 69 6e 6d 6f 62 69 6c 2e 72 75 } 		$a_01_1 = {2f 73 74 61 74 73 2f 61 64 76 2e 70 68 70 20 71 73 74 73 7a 64 3d } 		$a_01_2 = {63 68 65 63 6b 63 6f 6d 61 6e 64 } 		$a_01_3 = {61 6e 64 72 6f 69 64 2e 74 65 6c 65 70 68 6f 6e 79 2e 67 73 6d 2e 53 6d 73 4d 61 6e 61 67 65 72 } 		$a_01_4 = {72 65 75 6c 74 75 72 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}