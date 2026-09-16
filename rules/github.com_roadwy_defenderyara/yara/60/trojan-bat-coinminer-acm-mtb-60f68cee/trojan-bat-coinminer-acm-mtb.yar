rule Trojan_BAT_CoinMiner_ACM_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.ACM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 02 7b 5b 01 00 04 6a 58 06 20 ?? ?? ?? 00 64 0a e0 06 20 ?? ?? ?? 2f 5c 0a 47 02 02 7b 5b 01 00 04 06 } 		$a_01_1 = {52 00 65 00 61 00 6c 00 55 00 49 00 2d 00 49 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 65 00 72 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}