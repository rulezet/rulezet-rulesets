rule Trojan_BAT_CoinMiner_ACM_MTB_3{
	meta:
		description = "Trojan:BAT/CoinMiner.ACM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b 2b 2b 30 1b 2c f9 1e 2c f6 2b 2b 2b 30 2b 31 2b 36 75 01 00 00 1b 2b 36 19 2c 0f 16 2d e1 2b 31 16 2b 31 8e 69 28 ?? ?? ?? 0a 07 2a 28 ?? ?? ?? 06 2b ce 0a 2b cd 28 ?? ?? ?? 0a 2b ce 06 2b cd 6f ?? ?? ?? 0a 2b c8 28 ?? ?? ?? 06 2b c3 0b 2b c7 07 2b cc } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}