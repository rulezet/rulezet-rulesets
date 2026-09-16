rule Trojan_Win32_TrickBot_CB_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c6 51 03 de 89 44 24 2c e8 ?? ?? ?? ?? 83 c4 04 50 e8 ?? ?? ?? ?? 8a 08 83 c4 0c 33 d2 84 c9 74 ?? 8d 64 24 00 8b ea c1 e5 13 c1 ea 0d 0b d5 80 f9 61 0f b6 c9 72 ?? 83 e9 20 03 d1 8a 48 01 40 84 c9 75 ?? 81 fa } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}