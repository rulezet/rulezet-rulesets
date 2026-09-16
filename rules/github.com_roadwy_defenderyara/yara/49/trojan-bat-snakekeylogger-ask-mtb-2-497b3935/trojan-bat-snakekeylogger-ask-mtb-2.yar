rule Trojan_BAT_Snakekeylogger_ASK_MTB_2{
	meta:
		description = "Trojan:BAT/Snakekeylogger.ASK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0d 16 13 04 2b 32 09 08 17 8d 19 00 00 01 25 16 11 04 8c 5d 00 00 01 a2 14 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 1f 10 28 ?? ?? ?? 0a 86 6f ?? ?? ?? 0a 00 11 04 17 d6 13 04 } 		$a_01_1 = {42 00 61 00 73 00 69 00 63 00 2e 00 43 00 6f 00 6e 00 73 00 74 00 61 00 6e 00 74 00 73 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}