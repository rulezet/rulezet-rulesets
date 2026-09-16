rule Trojan_Win32_Nedsym_G{
	meta:
		description = "Trojan:Win32/Nedsym.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {75 af 6a 04 68 00 10 00 00 68 54 96 01 00 6a 00 e8 ?? ?? ?? ?? 89 45 f0 } 		$a_01_1 = {58 ff d0 85 c0 75 1d 8b 7d 0c 8a 07 0c 20 3c 74 75 09 c6 05 } 		$a_01_2 = {85 c0 75 06 8b 5c ee 6c eb 2e 43 81 fb e7 03 00 00 75 df 57 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=2
 
}