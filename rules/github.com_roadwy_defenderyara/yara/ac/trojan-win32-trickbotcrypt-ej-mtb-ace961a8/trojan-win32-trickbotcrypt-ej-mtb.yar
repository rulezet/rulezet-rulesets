rule Trojan_Win32_TrickBotCrypt_EJ_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 04 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 18 8b 5c 24 1c 2b d0 a1 ?? ?? ?? ?? 2b d3 8b 5c 24 20 2b d0 a1 ?? ?? ?? ?? 03 d3 03 d0 8b 44 24 10 8a 1c 28 8a 14 0a 32 da 88 1c 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}