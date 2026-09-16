rule Trojan_BAT_VIPKeylogger_ACH_MTB_2{
	meta:
		description = "Trojan:BAT/VIPKeylogger.ACH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {6c 5b 13 0d 02 11 15 11 17 6f ?? 00 00 0a 13 18 12 18 28 ?? 00 00 0a 16 32 19 12 18 28 ?? 00 00 0a 16 32 0f 12 18 28 ?? 00 00 0a 16 fe 04 16 fe 01 2b 01 16 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}