rule Trojan_Win32_Almanahe_C{
	meta:
		description = "Trojan:Win32/Almanahe.C,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {74 50 89 75 e4 81 7d e4 d0 04 00 00 73 17 8b 45 e4 8d 80 ?? ?? ?? ?? 33 c9 8a 08 83 f1 23 88 08 ff 45 e4 eb e0 56 8d 45 e4 50 68 00 26 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}