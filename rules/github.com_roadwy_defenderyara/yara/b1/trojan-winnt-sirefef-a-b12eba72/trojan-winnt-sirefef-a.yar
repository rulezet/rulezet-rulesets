rule Trojan_WinNT_Sirefef_A{
	meta:
		description = "Trojan:WinNT/Sirefef.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {c7 06 56 01 00 c0 5f } 		$a_01_1 = {8d 48 34 eb 02 33 c9 8b 44 24 08 85 c0 74 05 83 c0 34 eb 02 33 c0 6a 01 51 50 ff 15 } 		$a_03_2 = {83 c3 f8 83 c7 02 ?? c7 06 03 00 00 a0 66 89 5e 04 66 89 7e 0c ff 15 } 		$a_01_3 = {5f 00 5f 00 6d 00 61 00 78 00 2b 00 2b 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_01_3  & 1)*1) >=3
 
}