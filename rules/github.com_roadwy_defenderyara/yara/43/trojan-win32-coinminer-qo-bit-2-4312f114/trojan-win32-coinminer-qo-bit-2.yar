rule Trojan_Win32_CoinMiner_QO_bit_2{
	meta:
		description = "Trojan:Win32/CoinMiner.QO!bit,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {73 74 72 61 74 75 6d 2b 74 63 70 3a 2f 2f 78 6d 72 2e 70 6f 6f 6c 2e 6d 69 6e 65 72 67 61 74 65 2e 63 6f 6d 3a } 		$a_01_1 = {5c 4d 69 63 72 6f 73 6f 66 74 5c 57 69 6e 64 6f 77 73 5c 53 74 61 72 74 20 4d 65 6e 75 5c 50 72 6f 67 72 61 6d 73 5c 53 74 61 72 74 75 70 5c } 		$a_01_2 = {55 73 61 67 65 3a 20 78 6d 72 69 67 20 5b 4f 50 54 49 4f 4e 53 5d } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}