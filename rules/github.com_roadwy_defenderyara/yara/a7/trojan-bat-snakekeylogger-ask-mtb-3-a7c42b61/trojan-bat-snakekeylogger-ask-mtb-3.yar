rule Trojan_BAT_Snakekeylogger_ASK_MTB_3{
	meta:
		description = "Trojan:BAT/Snakekeylogger.ASK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {06 00 7e 01 00 00 04 6f ?? 00 00 0a 05 16 03 8e 69 6f ?? 00 00 0a 0a 06 0b 2b 00 } 		$a_03_1 = {7e 02 00 00 04 28 ?? 00 00 0a 02 6f ?? 00 00 0a 6f ?? 00 00 0a 0a 7e 01 00 00 04 06 6f ?? 00 00 0a 00 7e 01 00 00 04 18 6f } 		$a_01_2 = {46 00 72 00 6f 00 67 00 63 00 6f 00 69 00 6e 00 57 00 61 00 6c 00 6c 00 65 00 74 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}