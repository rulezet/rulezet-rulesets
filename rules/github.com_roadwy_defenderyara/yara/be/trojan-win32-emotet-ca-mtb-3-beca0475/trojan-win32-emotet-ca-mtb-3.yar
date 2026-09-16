rule Trojan_Win32_Emotet_CA_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.CA!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {81 e3 c8 20 6e 3b 31 d8 89 d3 c1 e3 19 c1 fb 1f 81 e3 90 41 dc 76 31 d8 c1 e2 18 c1 fa 1f 81 e2 20 83 b8 ed 31 d0 0f b6 11 41 85 d2 0f } 		$a_01_1 = {8b 06 01 d8 8b 55 e4 30 10 43 8b 06 3b 58 f4 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}