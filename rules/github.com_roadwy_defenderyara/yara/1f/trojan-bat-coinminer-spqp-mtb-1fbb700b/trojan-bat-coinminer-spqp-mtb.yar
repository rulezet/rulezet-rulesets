rule Trojan_BAT_CoinMiner_SPQP_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.SPQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {7e ce 07 00 04 7e cf 07 00 04 7e d0 07 00 04 61 7e d1 07 00 04 40 0d 00 00 00 7e 43 00 00 04 13 16 7e d2 07 00 04 58 00 6a 58 13 05 11 04 7e 45 00 00 04 13 17 7e d3 07 00 04 7e d4 07 00 04 7e d5 07 00 04 61 7e d6 07 00 04 40 0d 00 00 00 7e 43 00 00 04 13 17 7e d7 07 00 04 58 00 6f ?? ?? ?? 0a 11 05 28 ?? ?? ?? 0a 11 06 28 ?? ?? ?? 0a 3a 82 ff ff ff } 	condition:
		((#a_03_0  & 1)*4) >=4
 
}