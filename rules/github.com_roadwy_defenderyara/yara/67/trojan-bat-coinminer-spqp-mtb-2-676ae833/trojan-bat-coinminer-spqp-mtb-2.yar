rule Trojan_BAT_CoinMiner_SPQP_MTB_2{
	meta:
		description = "Trojan:BAT/CoinMiner.SPQP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 03 00 00 "
		
	strings :
		$a_03_0 = {08 03 2d 18 07 06 28 ?? ?? ?? 0a 72 cb 09 00 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 2b 16 07 06 28 ?? ?? ?? 0a 72 cb 09 00 70 6f ?? ?? ?? 0a 6f ?? ?? ?? 0a 17 73 34 00 00 0a 0d 09 02 16 02 8e 69 } 		$a_81_1 = {70 68 6e 69 70 68 70 63 73 69 76 6a 74 79 79 63 67 63 6c 6a 66 70 68 61 } 		$a_01_2 = {65 00 76 00 62 00 61 00 70 00 7a 00 68 00 6f 00 6e 00 75 00 77 00 75 00 68 00 69 00 65 00 75 00 } 	condition:
		((#a_03_0  & 1)*10+(#a_81_1  & 1)*2+(#a_01_2  & 1)*2) >=14
 
}