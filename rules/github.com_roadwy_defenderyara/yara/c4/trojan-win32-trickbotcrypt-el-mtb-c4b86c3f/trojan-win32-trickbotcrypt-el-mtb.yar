rule Trojan_Win32_TrickBotCrypt_EL_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 44 24 1c 83 c0 fe 0f af 05 ?? ?? ?? ?? 2b d5 8b e9 03 ea 8a 14 28 8a 03 32 c2 8b 54 24 24 88 03 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}