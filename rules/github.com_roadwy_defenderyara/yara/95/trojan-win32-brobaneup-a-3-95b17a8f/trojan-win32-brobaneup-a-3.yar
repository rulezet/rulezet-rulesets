rule Trojan_Win32_BrobanEup_A_3{
	meta:
		description = "Trojan:Win32/BrobanEup.A,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {2f 65 75 70 64 73 2e 70 68 70 } 		$a_01_1 = {3c 2f 62 6f 6c 61 68 74 6d 6c 3e } 		$a_01_2 = {70 61 67 61 64 6f 72 2e 63 6f 6d 2e 62 72 } 		$a_01_3 = {2f 69 6e 64 65 78 31 2e 70 68 70 3f 6c 6f 67 3d } 		$a_01_4 = {5b 67 66 6f 72 63 65 5f 64 6c 6c 5d 3a } 		$a_01_5 = {62 6f 6c 65 74 6f } 		$a_01_6 = {73 65 67 75 6e 64 61 76 69 61 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}