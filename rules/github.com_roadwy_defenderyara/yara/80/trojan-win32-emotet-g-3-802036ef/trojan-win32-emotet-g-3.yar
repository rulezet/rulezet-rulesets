rule Trojan_Win32_Emotet_G_3{
	meta:
		description = "Trojan:Win32/Emotet.G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {79 09 81 ce 00 30 00 00 89 70 25 80 7c 24 ?? 00 75 44 8a 4c 24 ?? 80 c1 27 80 f9 06 } 		$a_01_1 = {69 c9 0d 66 19 00 0f be d2 40 8d 8c 11 5f f3 6e 3c 8a 10 84 d2 75 e9 } 		$a_03_2 = {bf 37 7e 13 a4 90 13 64 a1 30 00 00 00 8b 48 0c 56 8b 71 0c 83 7e 18 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}