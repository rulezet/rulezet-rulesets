rule TrojanSpy_AndroidOS_Bray_H_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/Bray.H!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {35 03 14 00 34 14 03 00 12 04 48 05 07 03 6e 20 ?? ?? 48 00 0a 06 b7 65 8d 55 4f 05 07 03 d8 03 03 01 d8 04 04 01 28 ed } 		$a_01_1 = {67 65 74 4d 65 73 73 61 67 65 42 6f 64 79 } 		$a_01_2 = {67 65 74 4f 72 69 67 69 6e 61 74 69 6e 67 41 64 64 72 65 73 73 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}