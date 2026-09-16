rule Trojan_BAT_CoinMiner_AC_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 88 03 00 04 13 00 7e 89 03 00 04 7e 8a 03 00 04 7e 8b 03 00 04 61 7e 8c 03 00 04 40 0d 00 00 00 7e 42 00 00 04 13 00 7e 8d 03 00 04 58 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}