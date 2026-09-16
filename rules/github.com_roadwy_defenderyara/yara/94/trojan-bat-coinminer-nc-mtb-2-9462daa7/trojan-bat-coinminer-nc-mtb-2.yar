rule Trojan_BAT_CoinMiner_NC_MTB_2{
	meta:
		description = "Trojan:BAT/CoinMiner.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {6f 5e 00 00 0a 17 73 ?? ?? ?? 0a 0c 08 02 16 02 8e 69 6f 56 00 00 0a } 		$a_01_1 = {68 00 74 00 74 00 70 00 3a 00 2f 00 2f 00 31 00 38 00 35 00 2e 00 31 00 37 00 32 00 2e 00 31 00 32 00 38 00 2e 00 31 00 31 00 2f 00 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}