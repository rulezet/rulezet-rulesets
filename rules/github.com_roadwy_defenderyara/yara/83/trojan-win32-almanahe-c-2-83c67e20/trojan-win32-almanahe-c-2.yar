rule Trojan_Win32_Almanahe_C_2{
	meta:
		description = "Trojan:Win32/Almanahe.C,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {81 7d e4 00 09 00 00 73 17 8b 45 e4 8d 80 ?? ?? ?? ?? 33 c9 8a 08 83 f1 3a 88 08 ff 45 e4 eb e0 } 		$a_01_1 = {5f 5f 44 4c 5f 43 4f 52 45 34 47 41 45 58 5f 4d 55 54 45 58 5f 5f 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}