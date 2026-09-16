rule Trojan_Win32_CoinMiner_PK_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.PK!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 6c 61 69 79 61 77 61 6b 75 61 6e 67 61 00 } 		$a_01_1 = {00 5c 77 6b 73 7a 2e 69 6e 69 00 } 		$a_01_2 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 67 65 74 2e 62 69 2d 63 68 69 2e 63 6f 6d 3a 33 33 33 33 20 2d 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}