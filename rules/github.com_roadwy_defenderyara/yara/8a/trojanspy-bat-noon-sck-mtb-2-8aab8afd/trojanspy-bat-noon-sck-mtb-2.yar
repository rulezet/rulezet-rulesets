rule TrojanSpy_BAT_Noon_SCK_MTB_2{
	meta:
		description = "TrojanSpy:BAT/Noon.SCK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 06 17 d6 13 06 11 06 06 6f 3b 00 00 0a fe 04 13 08 11 08 2d 9e } 		$a_81_1 = {43 6f 6d 62 6f 42 6f 78 42 69 6e 64 2e 4d 61 69 6e 46 6f 72 6d 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}