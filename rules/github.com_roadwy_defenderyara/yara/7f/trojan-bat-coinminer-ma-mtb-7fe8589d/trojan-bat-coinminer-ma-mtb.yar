rule Trojan_BAT_CoinMiner_MA_MTB{
	meta:
		description = "Trojan:BAT/CoinMiner.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_81_0 = {68 74 74 70 3a 2f 2f 31 38 35 2e 31 37 32 2e 31 32 38 2e 31 31 } 		$a_01_1 = {31 31 65 61 66 31 37 32 2d 31 31 64 63 2d 34 35 32 32 2d 62 33 61 65 2d 62 39 37 32 37 38 35 64 65 32 64 62 } 	condition:
		((#a_81_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}