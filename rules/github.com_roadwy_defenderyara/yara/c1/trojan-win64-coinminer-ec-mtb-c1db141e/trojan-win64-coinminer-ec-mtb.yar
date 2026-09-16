rule Trojan_Win64_CoinMiner_EC_MTB{
	meta:
		description = "Trojan:Win64/CoinMiner.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 02 00 00 "
		
	strings :
		$a_01_0 = {4c 89 45 d8 41 0f ba e0 09 41 8b c7 45 8b c3 45 8b cc 0f a2 45 0f 43 c7 45 33 d2 89 45 d0 89 5d d4 89 4d d8 33 c9 89 55 dc 41 8b c7 0f a2 41 0f ba e2 09 4c 89 55 d0 } 		$a_01_1 = {4c 8d 65 d0 4c 8b eb 4d 03 e0 49 f7 dc 49 f7 dd 43 8d 04 16 30 03 85 c9 75 41 } 	condition:
		((#a_01_0  & 1)*4+(#a_01_1  & 1)*3) >=7
 
}