rule Trojan_BAT_CoinMiner_NCI_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.NCI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {28 26 00 00 0a 0c 06 28 ?? 00 00 06 73 ?? 00 00 0a 0d 08 8d ?? 00 00 01 13 04 09 11 04 28 ?? 00 00 06 08 6f ?? 00 00 0a 26 } 		$a_01_1 = {55 6c 74 72 61 49 53 4f } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}