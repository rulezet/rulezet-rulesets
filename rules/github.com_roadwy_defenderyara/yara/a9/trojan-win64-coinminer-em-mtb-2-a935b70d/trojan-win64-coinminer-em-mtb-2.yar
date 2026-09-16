rule Trojan_Win64_CoinMiner_EM_MTB_2{
	meta:
		description = "Trojan:Win64/CoinMiner.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {6d 69 6e 69 6e 67 2e 73 75 62 73 63 72 69 62 65 } 		$a_01_1 = {63 70 75 6d 69 6e 65 72 2f 31 2e 30 2e 34 } 		$a_01_2 = {58 2d 4d 69 6e 69 6e 67 2d 45 78 74 65 6e 73 69 6f 6e 73 3a 20 6d 69 64 73 74 61 74 65 } 		$a_01_3 = {58 2d 4c 6f 6e 67 2d 50 6f 6c 6c 69 6e 67 } 		$a_01_4 = {58 2d 52 65 6a 65 63 74 2d 52 65 61 73 6f 6e } 		$a_01_5 = {58 2d 53 74 72 61 74 75 6d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}