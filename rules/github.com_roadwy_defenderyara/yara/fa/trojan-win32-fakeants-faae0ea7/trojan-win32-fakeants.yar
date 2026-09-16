rule Trojan_Win32_FakeAnts{
	meta:
		description = "Trojan:Win32/FakeAnts,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 74 24 0e 8a f1 28 36 81 7c 24 0a a5 26 00 00 } 		$a_01_1 = {8b 74 24 0e 00 36 ff 44 24 0e d1 e9 d1 e9 d1 e9 } 		$a_01_2 = {72 b2 ff 44 24 0a 81 7c 24 0a 75 27 00 00 76 8f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}