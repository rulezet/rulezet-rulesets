rule Trojan_Win32_CoinMiner_PW_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.PW!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2e 64 6f 77 6e 30 31 31 36 2e 69 6e 66 6f } 		$a_01_1 = {5b 25 64 5d 20 25 73 20 6b 69 6c 6c 20 70 72 6f 63 3a 20 25 73 2c 66 69 6c 65 3a 20 25 73 } 		$a_01_2 = {64 65 6c 20 2f 46 20 2f 41 52 48 53 20 22 25 73 22 } 		$a_01_3 = {2f 43 20 70 69 6e 67 20 31 32 37 2e 30 2e 30 2e 31 20 2d 6e 20 36 20 26 20 74 61 73 6b 6b 69 6c 6c 20 2d 66 20 2f 69 6d 20 63 6f 6e 69 6d 65 2e 65 78 65 20 2f 69 6d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}