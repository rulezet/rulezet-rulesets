rule TrojanSpy_AndroidOS_SAgnt_D_MTB{
	meta:
		description = "TrojanSpy:AndroidOS/SAgnt.D!MTB,SIGNATURE_TYPE_DEXHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {13 06 0a 00 83 66 cd 64 8a 44 b7 04 71 20 ?? 00 42 00 0c 02 71 10 ?? ?? 02 00 0c 02 d8 00 00 01 28 ?? 71 20 } 		$a_01_1 = {45 69 72 76 41 70 70 43 6f 6d 70 6f 6e 65 6e 74 46 61 63 74 6f 72 79 53 74 75 62 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}