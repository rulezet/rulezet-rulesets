rule Trojan_BAT_CoinMiner_NC_MTB_3{
	meta:
		description = "Trojan:BAT/CoinMiner.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 28 00 00 0a 6f ?? ?? 00 0a 13 04 73 ?? ?? 00 0a 13 05 11 05 11 04 28 ?? ?? 00 06 73 ?? ?? 00 0a 13 06 00 11 06 02 28 ?? ?? 00 06 02 8e 69 6f ?? ?? 00 0a 00 11 06 6f ?? ?? 00 0a 00 11 05 6f ?? ?? 00 0a 13 07 de 4e } 		$a_03_1 = {28 1b 00 00 0a 0a 73 ?? 00 00 0a 0b 06 02 6f ?? 00 00 0a 0c 08 14 fe 01 13 05 11 05 2d 11 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5) >=10
 
}