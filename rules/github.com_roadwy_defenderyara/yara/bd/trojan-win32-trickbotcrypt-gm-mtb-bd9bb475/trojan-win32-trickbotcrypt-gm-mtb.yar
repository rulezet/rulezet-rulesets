rule Trojan_Win32_TrickBotCrypt_GM_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 1c 0e 0f b6 c3 03 c7 33 d2 f7 35 ?? ?? ?? ?? 8b fa 8a 04 0f 88 04 0e 88 1c 0f 0f b6 04 0e 0f b6 d3 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 18 8a 1c 28 8a 14 0a 32 da 88 1c 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}