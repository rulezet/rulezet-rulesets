rule Trojan_Win32_Emotet_G{
	meta:
		description = "Trojan:Win32/Emotet.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {6a 33 e8 00 00 00 00 83 04 24 05 cb 4c 8b 55 08 41 8b 42 3c } 		$a_03_1 = {8a 04 16 32 81 ?? ?? ?? ?? 41 88 02 83 f9 ?? 72 02 } 		$a_01_2 = {c6 00 e9 8b d7 2b 54 24 30 81 c6 ff 0f 00 00 83 ea 55 89 50 01 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}