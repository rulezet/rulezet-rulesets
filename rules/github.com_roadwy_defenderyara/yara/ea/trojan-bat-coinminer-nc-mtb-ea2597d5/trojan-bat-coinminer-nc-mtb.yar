rule Trojan_BAT_CoinMiner_NC_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {72 96 04 00 70 80 ?? ?? ?? 04 20 01 00 00 00 16 39 ?? ?? ?? ff 26 38 78 ff ff ff 72 ?? ?? ?? 70 80 01 00 00 04 38 d6 ff ff ff } 		$a_01_1 = {6e 69 6d 71 65 46 41 48 38 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1) >=6
 
}