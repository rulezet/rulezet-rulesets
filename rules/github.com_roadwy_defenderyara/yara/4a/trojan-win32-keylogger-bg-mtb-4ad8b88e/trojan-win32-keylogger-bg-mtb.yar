rule Trojan_Win32_KeyLogger_BG_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.BG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2b 33 71 b5 97 6f 33 3f 65 59 e5 4a bd 35 bf c9 a8 1c ad 89 2a 3d fb fc fa a0 68 10 a7 38 08 00 2b 33 71 b5 5b d1 b8 19 3c 0a ef 4b } 		$a_01_1 = {fe 11 7a 90 a5 08 12 4b ab 76 e5 f0 4d b4 80 30 06 a8 d6 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}