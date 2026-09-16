rule Trojan_Win32_CoinMiner_AZ_bit{
	meta:
		description = "Trojan:Win32/CoinMiner.AZ!bit,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 69 6e 65 72 20 25 73 26 6d 5f 70 72 6f 63 6e 75 6d 3d 25 64 26 6d 5f 65 78 69 73 74 73 3d 25 73 } 		$a_01_1 = {67 2e 64 69 73 67 6f 67 6f 77 65 62 2e 63 6f 6d 2f } 		$a_01_2 = {74 61 73 6b 6b 69 6c 6c 20 2f 66 20 2f 69 6d 20 6d 73 69 65 78 65 76 2e 65 78 65 } 		$a_01_3 = {44 6f 77 6e 6c 6f 61 64 41 6e 64 52 75 6e 3a 20 25 73 3a 20 25 73 3a } 		$a_01_4 = {73 63 72 69 70 74 73 5c 6d 69 6e 65 72 2e 6c 75 61 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}