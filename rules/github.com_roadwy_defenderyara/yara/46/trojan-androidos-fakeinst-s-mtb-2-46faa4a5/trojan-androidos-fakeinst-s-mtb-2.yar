rule Trojan_AndroidOS_FakeInst_S_MTB_2{
	meta:
		description = "Trojan:AndroidOS/FakeInst.S!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {76 6e 69 74 6f 75 72 69 73 74 2e 63 6f 6d } 		$a_01_1 = {61 70 69 63 68 65 63 6b 73 75 62 73 2e 6d 6f 64 6f 62 6f 6d 63 6f 2e 63 6f 6d 2f 63 68 65 63 6b 2d 73 75 62 73 3f 63 6f 75 6e 74 72 79 3d 72 6f 6d 61 6e 69 61 } 		$a_01_2 = {43 6f 6e 66 69 72 74 69 6e 52 65 63 65 69 76 65 72 } 		$a_01_3 = {46 4c 41 47 5f 43 4f 4e 46 49 52 4d 5f 4b 57 31 } 		$a_01_4 = {4e 68 61 6e 52 65 63 65 69 76 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}