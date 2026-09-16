rule Trojan_Win32_CoinMiner_QO_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.QO!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 31 35 2c 31 31 36 2c 31 31 34 2c 39 37 2c 31 31 36 2c 31 31 37 2c 31 30 39 2c 34 33 2c 31 31 36 2c 39 39 2c 31 31 32 2c 35 38 } 		$a_01_1 = {5c 46 6f 6e 74 73 5c 31 73 61 73 73 2e 65 78 65 } 		$a_01_2 = {5c 4d 53 42 75 69 6c 64 5c 53 65 72 76 69 63 65 73 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}