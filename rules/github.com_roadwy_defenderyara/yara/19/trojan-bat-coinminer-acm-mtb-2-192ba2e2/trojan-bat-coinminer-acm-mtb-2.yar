rule Trojan_BAT_CoinMiner_ACM_MTB_2{
	meta:
		description = "Trojan:BAT/CoinMiner.ACM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {16 13 06 2b 27 11 05 11 06 9a 13 07 00 11 07 73 17 00 00 0a 13 08 11 08 6f ?? ?? ?? 0a 13 09 11 09 2c 02 16 0a 00 11 06 17 58 13 06 11 06 11 05 8e 69 32 d1 } 		$a_01_1 = {78 00 75 00 6d 00 72 00 65 00 } 		$a_01_2 = {7a 00 75 00 6d 00 6c 00 72 00 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}