rule Trojan_BAT_Keylogger_NKL_MTB_2{
	meta:
		description = "Trojan:BAT/Keylogger.NKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f ca 00 00 06 2c 06 73 ?? 00 00 0a 7a 03 11 04 1f 50 58 28 ?? 00 00 0a 13 09 03 11 04 1f 54 58 28 ?? 00 00 0a 13 0a 16 } 		$a_01_1 = {53 65 63 75 72 65 48 6f 72 69 7a 6f 6e 73 2e 67 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}