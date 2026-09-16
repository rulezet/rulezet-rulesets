rule Trojan_Win32_Zbot_AZB_MTB_2{
	meta:
		description = "Trojan:Win32/Zbot.AZB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {c1 e1 02 d3 e0 c1 e1 03 23 c8 33 ce f7 e3 83 ef 72 49 c1 e0 04 23 d9 } 		$a_01_1 = {f7 e1 33 f6 d3 ee 0b cf 42 d1 e9 d3 e6 8d 0c 80 d3 e3 8d 93 da 00 00 00 33 c9 8d 0c 89 ba 95 15 de f4 c1 e0 04 42 81 ef 7c 2b 00 00 c1 e7 05 83 e8 24 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*2) >=3
 
}