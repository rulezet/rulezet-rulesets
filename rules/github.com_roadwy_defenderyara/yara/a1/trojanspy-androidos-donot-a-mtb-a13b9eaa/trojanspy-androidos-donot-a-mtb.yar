rule TrojanSpy_AndroidOS_DoNot_A_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/DoNot.A!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 68 65 6c 6c 6f 2f 75 70 6c 6f 61 64 } 		$a_01_1 = {63 6f 6d 2f 73 79 73 74 65 6d 2f 61 6e 64 72 6f 69 64 2f 75 70 64 61 74 65 72 2f 74 65 6e } 		$a_01_2 = {61 6c 72 61 64 64 6f 72 6e } 		$a_01_3 = {57 61 70 70 46 69 6c 65 53 65 6e 64 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}