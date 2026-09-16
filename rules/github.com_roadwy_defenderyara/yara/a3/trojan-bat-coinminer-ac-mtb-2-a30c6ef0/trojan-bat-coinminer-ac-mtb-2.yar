rule Trojan_BAT_CoinMiner_AC_MTB_2{
	meta:
		description = "Trojan:BAT/CoinMiner.AC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 22 11 23 9a 13 24 00 11 24 6f ?? ?? ?? 0a 11 21 6f ?? ?? ?? 0a fe 01 16 fe 01 13 25 11 25 2c 05 00 16 13 08 00 00 11 23 17 58 13 23 11 23 11 22 8e 69 32 cb } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}