rule TrojanSpy_AndroidOS_InfoStealer_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/InfoStealer.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_00_0 = {4c 63 6f 6d 2f 73 61 6b 75 2f 61 70 70 2f 70 6f 3b } 		$a_00_1 = {2f 61 70 69 2f 7a 68 75 61 6e 5f 62 6f } 		$a_00_2 = {63 61 6c 6c 44 75 72 61 74 69 6f 6e 53 74 72 } 		$a_01_3 = {73 6d 73 5f 73 74 72 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}