rule Trojan_Win64_CoinMiner_NC_MTB_2{
	meta:
		description = "Trojan:Win64/CoinMiner.NC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 31 c0 8b 05 ?? ?? ?? ?? 48 83 c4 28 48 8b 4c 24 08 48 8b 54 24 10 4c 8b 44 24 18 4c 8b 4c 24 20 49 89 ca 8f } 		$a_03_1 = {58 48 89 4c 24 08 48 89 54 24 10 4c 89 44 24 18 4c 89 4c 24 20 48 83 ec 28 8b 0d ?? ?? ?? ?? e8 a8 65 00 00 89 05 } 		$a_01_2 = {53 6c 65 65 70 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1) >=5
 
}