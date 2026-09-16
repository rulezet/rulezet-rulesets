rule TrojanSpy_AndroidOS_Svpeng_B_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Svpeng.B!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {68 69 74 6c 65 72 5f 62 61 63 6b 6d 79 62 65 77 69 6c 6c 63 68 61 6e 67 65 64 73 6f 6f 6e } 		$a_00_1 = {73 74 61 72 74 70 6c 65 61 73 65 32 } 		$a_00_2 = {79 6e 6f 74 5f 62 75 74 74 6f 6e } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}