rule Trojan_Win32_CoinMiner_PW_bit_2{
	meta:
		description = "Trojan:Win32/CoinMiner.PW!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_01_0 = {2d 6f 20 73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 25 73 20 2d 75 20 25 73 } 		$a_01_1 = {3a 2f 2f 25 73 3a 38 38 38 38 2f 6d 64 35 2e 74 78 74 } 		$a_01_2 = {3a 2f 2f 25 73 3a 38 38 38 38 2f 78 6d 72 6f 6b 2e 74 78 74 } 		$a_01_3 = {70 75 62 79 75 6e 2e 63 6f 6d 2f 64 79 6e 64 6e 73 2f 67 65 74 69 70 } 		$a_01_4 = {61 63 63 65 73 73 20 73 69 6e 61 20 62 6c 6f 67 20 6f 6b 2c 20 68 6f 73 74 3a 20 25 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=3
 
}