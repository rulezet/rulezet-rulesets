rule Trojan_Win32_BrobanEup_A_2{
	meta:
		description = "Trojan:Win32/BrobanEup.A,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 00 6a 01 ff 74 24 0c b8 44 33 22 11 ff d0 c3 } 		$a_03_1 = {8b 4e 28 03 4d ?? 53 6a 11 68 ?? ?? ?? ?? 50 ff 75 08 89 0d ?? ?? ?? ?? ff d7 } 		$a_03_2 = {8b 4f 28 03 4d ?? 53 6a 11 68 ?? ?? ?? ?? 50 ff 75 08 89 0d ?? ?? ?? ?? ff d6 } 	condition:
		((#a_01_0  & 1)*10+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=11
 
}