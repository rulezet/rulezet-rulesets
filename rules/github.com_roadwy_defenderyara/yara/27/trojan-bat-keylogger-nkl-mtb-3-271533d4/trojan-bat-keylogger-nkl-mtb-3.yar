rule Trojan_BAT_Keylogger_NKL_MTB_3{
	meta:
		description = "Trojan:BAT/Keylogger.NKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f e2 00 00 0a 0b 07 16 73 ?? ?? 00 0a 13 0b 11 0b 73 ?? ?? 00 0a 13 04 7e ?? ?? 00 04 11 04 7e ?? ?? 00 04 11 04 28 ?? ?? 00 06 28 ?? ?? 00 06 13 05 } 		$a_01_1 = {41 6e 61 72 63 68 79 2e 67 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}