rule Trojan_BAT_AsyncRAT_AD_MTB{
	meta:
		description = "Trojan:BAT/AsyncRAT.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_03_0 = {32 e7 06 7e ?? 00 00 04 1f 1f 5f 63 8d ?? 00 00 01 0b 7e ?? 00 00 04 13 04 2b 5f 07 11 04 02 11 04 7e ?? 00 00 04 1f 1f 5f 62 6f ?? 00 00 0a 28 } 	condition:
		((#a_03_0  & 1)*3) >=3
 
}