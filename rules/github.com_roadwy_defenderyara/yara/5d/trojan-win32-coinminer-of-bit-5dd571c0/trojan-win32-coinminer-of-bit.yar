rule Trojan_Win32_CoinMiner_OF_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.OF!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {2f 74 72 20 22 72 75 6e 64 6c 6c 33 32 2e 65 78 65 20 75 72 6c 2e 64 6c 6c 2c 4f 70 65 6e 55 52 4c 41 } 		$a_01_1 = {73 68 75 74 64 6f 77 6e 20 2d 73 20 2d 74 20 31 } 		$a_03_2 = {50 72 6f 63 65 73 73 20 48 61 63 6b 65 72 [0-03] 41 6e 56 69 72 } 		$a_01_3 = {4c 53 31 6b 62 32 35 68 64 47 55 74 62 47 56 32 5a 57 77 39 4d 51 3d 3d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*2) >=3
 
}