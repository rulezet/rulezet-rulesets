rule Trojan_Win32_TrickBotCrypt_EI_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {88 14 38 8b 44 24 ?? 03 c3 89 44 24 ?? 0f b6 d2 8b c6 2b c1 0f b6 04 38 03 c2 33 d2 bb ?? ?? ?? ?? f7 f3 8b 44 24 ?? 2b 15 ?? ?? ?? ?? 03 54 24 30 03 d5 03 54 24 ?? 8a 14 3a 30 10 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}