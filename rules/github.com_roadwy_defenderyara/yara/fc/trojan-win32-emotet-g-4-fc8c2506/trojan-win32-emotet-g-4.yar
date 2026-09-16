rule Trojan_Win32_Emotet_G_4{
	meta:
		description = "Trojan:Win32/Emotet.G,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 03 00 00 "
		
	strings :
		$a_01_0 = {b8 25 49 92 24 f7 e6 2b f2 d1 ee 03 f2 c1 ee 03 56 } 		$a_01_1 = {25 00 73 00 5c 00 4d 00 69 00 63 00 72 00 6f 00 73 00 6f 00 66 00 74 00 5c 00 6d 00 73 00 64 00 62 00 25 00 78 00 2e 00 65 00 78 00 65 00 } 		$a_01_2 = {0f b6 1c 0a 33 de 69 db 01 01 01 01 41 8b f3 3b c8 72 ed 5b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*10+(#a_01_2  & 1)*10) >=21
 
}