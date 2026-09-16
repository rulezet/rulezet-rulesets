rule Trojan_Win32_CoinMiner_DH_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.DH!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {44 37 44 53 56 63 4c 45 31 6a 46 7a 35 75 65 67 35 59 34 35 6b 33 42 6d 36 68 72 36 35 76 33 74 65 70 } 		$a_01_1 = {2d 61 20 79 65 73 63 72 79 70 74 20 2d 6f } 		$a_01_2 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 79 65 73 63 72 79 70 74 2e 6e 61 2e 6d 69 6e 65 2e 7a 70 6f 6f 6c 2e 63 61 3a 36 32 33 33 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}