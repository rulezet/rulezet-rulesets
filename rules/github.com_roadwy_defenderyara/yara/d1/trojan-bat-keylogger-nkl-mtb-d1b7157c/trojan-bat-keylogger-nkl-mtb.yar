rule Trojan_BAT_Keylogger_NKL_MTB{
	meta:
		description = "Trojan:BAT/Keylogger.NKL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 15 00 00 0a 6f ?? 00 00 0a 00 73 ?? 00 00 0a 13 04 00 11 04 08 6f ?? 00 00 0a 17 73 ?? 00 00 0a 13 05 00 11 05 07 16 07 8e 69 6f ?? 00 00 0a } 		$a_01_1 = {46 78 34 62 65 74 61 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}