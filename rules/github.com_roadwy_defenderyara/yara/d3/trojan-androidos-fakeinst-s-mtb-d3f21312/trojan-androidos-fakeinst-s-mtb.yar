rule Trojan_AndroidOS_FakeInst_S_MTB{
	meta:
		description = "Trojan:AndroidOS/FakeInst.S!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {52 65 61 64 41 6c 6c 54 65 78 74 46 72 6f 6d 53 74 72 65 61 6d } 		$a_01_1 = {4d 79 50 68 6f 6e 65 43 6c 61 73 73 } 		$a_01_2 = {67 65 74 57 68 6f 72 65 50 68 6f 6e 65 } 		$a_01_3 = {63 6f 6d 2f 6c 6f 61 64 66 6f 6e 2f 66 69 6c 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}