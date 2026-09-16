rule Trojan_Win32_Coopop_B{
	meta:
		description = "Trojan:Win32/Coopop.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {00 49 45 4e 41 4d 45 00 00 53 45 54 00 49 53 4c 41 58 43 48 45 43 4b 00 00 49 45 2e 69 6e 69 00 } 		$a_01_1 = {8a 04 11 f6 d0 88 04 11 8b c1 49 85 c0 7f f1 } 		$a_03_2 = {68 1f 00 02 00 53 68 48 c1 00 10 68 01 00 00 80 89 ?? ?? 18 89 ?? ?? 24 ff 15 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}