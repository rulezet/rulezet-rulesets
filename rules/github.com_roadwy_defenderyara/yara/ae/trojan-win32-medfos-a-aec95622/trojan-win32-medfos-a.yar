rule Trojan_Win32_Medfos_A{
	meta:
		description = "Trojan:Win32/Medfos.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {c6 45 e0 69 (c6 45 e1 65|e9 90 16 c6 45 e1 65) 90 03 04 07 c6 45 e2 78 e9 90 16 c6 45 e2 78 } 		$a_03_1 = {68 00 30 00 00 (68 00 b0 04 00|e9 90 16 68 00 b0 04 00) } 		$a_03_2 = {69 ff c8 00 00 00 (57|e9 90 16 57) 90 03 04 07 a2 ?? ?? ?? ?? e9 90 16 a2 ?? ?? ?? ?? 90 03 02 05 ff 15 e9 90 16 ff 15 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}