rule TrojanSpy_BAT_Quasar_SO_MTB_2{
	meta:
		description = "TrojanSpy:BAT/Quasar.SO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {07 6f 27 00 00 0a 18 63 d4 8d 17 00 00 01 13 04 20 00 01 00 00 8d 19 00 00 01 13 05 16 13 07 2b 15 } 		$a_81_1 = {73 65 72 76 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}