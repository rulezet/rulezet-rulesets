rule TrojanSpy_BAT_Keylog_B{
	meta:
		description = "TrojanSpy:BAT/Keylog.B,SIGNATURE_TYPE_PEHSTR_EXT,14 00 14 00 02 00 00 "
		
	strings :
		$a_00_0 = {52 00 65 00 66 00 6c 00 65 00 63 00 74 00 20 00 4c 00 6f 00 67 00 67 00 65 00 72 00 } 		$a_01_1 = {4b 45 43 41 42 41 } 	condition:
		((#a_00_0  & 1)*5+(#a_01_1  & 1)*15) >=20
 
}