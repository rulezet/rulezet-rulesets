rule Trojan_BAT_CoinMiner_MA_MTB_2{
	meta:
		description = "Trojan:BAT/CoinMiner.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {08 11 07 07 11 07 9a 1f 10 28 ?? ?? ?? 0a 9c 11 07 17 58 13 07 11 07 07 8e 69 fe 04 13 08 11 08 2d de } 		$a_01_1 = {4d 69 6e 65 73 77 65 65 70 65 72 5f 57 69 6e 64 6f 77 73 46 6f 72 6d 73 41 70 70 } 		$a_01_2 = {67 65 74 5f 44 61 72 6b 52 65 64 } 		$a_01_3 = {67 65 74 5f 49 73 48 69 64 64 65 6e } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}