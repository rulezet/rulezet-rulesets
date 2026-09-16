rule Trojan_Win32_Medfos_A_2{
	meta:
		description = "Trojan:Win32/Medfos.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a 5c 39 48 (32 d8|e9 90 16 32 d8) 90 03 03 06 88 1c 32 e9 90 16 88 1c 32 90 03 01 04 42 e9 90 16 42 90 03 02 05 fe c0 e9 90 16 fe c0 90 03 03 06 83 ff 02 e9 90 16 83 ff 02 } 		$a_03_1 = {c6 45 f3 70 (c6 45 f4 6c|e9 90 16 c6 45 f4 6c) 90 03 04 07 c6 45 f5 6f e9 90 16 c6 45 f5 6f } 		$a_03_2 = {69 c0 e8 03 00 00 (a3 ?? ?? ??|?? e9 90 16 a3 ?? ??) ?? ?? 90 03 01 04 c3 e9 90 16 c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}