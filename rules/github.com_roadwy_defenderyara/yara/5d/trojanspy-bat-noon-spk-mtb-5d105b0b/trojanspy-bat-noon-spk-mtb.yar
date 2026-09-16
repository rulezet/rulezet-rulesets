rule TrojanSpy_BAT_Noon_SPK_MTB{
	meta:
		description = "TrojanSpy:BAT/Noon.SPK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 17 58 0b 00 07 02 7b a8 01 00 04 2f 06 07 19 fe 04 2b 01 16 0c 08 2d d2 } 		$a_81_1 = {51 4c 42 48 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}