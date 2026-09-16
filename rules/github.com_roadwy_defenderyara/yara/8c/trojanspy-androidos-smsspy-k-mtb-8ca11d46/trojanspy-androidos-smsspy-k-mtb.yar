rule TrojanSpy_AndroidOS_SmsSpy_K_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SmsSpy.K!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {73 6d 73 62 6f 6d 62 65 72 } 		$a_01_1 = {63 6f 6d 2f 64 72 6e 75 6c 6c 2f 66 63 6d 2f 73 6d 73 52 65 63 65 69 76 65 72 } 		$a_01_2 = {68 69 64 65 61 6c 6c } 		$a_01_3 = {50 4f 53 54 5f 4e 4f 54 4f 46 4f 43 41 54 49 4f 4e 53 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}