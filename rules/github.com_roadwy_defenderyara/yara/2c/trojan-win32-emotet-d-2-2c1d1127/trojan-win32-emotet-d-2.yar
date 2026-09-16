rule Trojan_Win32_Emotet_D_2{
	meta:
		description = "Trojan:Win32/Emotet.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_01_0 = {0f b6 1c 0e 33 da 69 db 01 01 01 01 41 8b d3 3b c8 72 ed } 		$a_01_1 = {b8 1f 85 eb 51 f7 e1 c1 ea 03 8a c2 6b d2 0d b3 19 f6 eb 2a c8 80 c1 61 88 0e 46 83 ef 01 8b ca 75 de } 		$a_01_2 = {0f b6 14 32 30 14 38 40 fe c3 3b 44 24 18 72 be } 		$a_00_3 = {25 00 73 00 5c 00 49 00 64 00 65 00 6e 00 74 00 69 00 74 00 69 00 65 00 73 00 5c 00 25 00 63 00 25 00 63 00 25 00 63 00 25 00 63 00 25 00 63 00 25 00 63 00 25 00 63 00 25 00 63 00 2e 00 65 00 78 00 65 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_00_3  & 1)*1) >=3
 
}