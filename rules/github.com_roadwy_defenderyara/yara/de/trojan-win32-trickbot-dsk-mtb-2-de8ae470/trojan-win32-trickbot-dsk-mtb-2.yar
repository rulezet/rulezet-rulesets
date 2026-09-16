rule Trojan_Win32_TrickBot_DSK_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBot.DSK!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {b8 db 4b 68 2f f7 e1 8b c1 2b c2 d1 e8 03 c2 c1 e8 04 6b c0 1b 8b d1 2b d0 8a 04 1a 30 04 31 83 c1 01 3b cf } 		$a_01_1 = {54 79 57 41 43 6b 38 62 74 7d 65 41 33 41 31 32 63 35 54 54 4a 76 4f 6d 59 62 45 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}