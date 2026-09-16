rule Trojan_Win32_BrobanEup_A{
	meta:
		description = "Trojan:Win32/BrobanEup.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {80 3b e9 75 0c 83 fe 05 72 07 8b c7 2b c3 01 43 01 8b cf 2b cb 83 e9 05 c6 04 1e e9 89 4c 1e 01 } 		$a_03_1 = {8b 03 3d 48 45 41 44 74 ?? 3d 50 4f 53 54 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}