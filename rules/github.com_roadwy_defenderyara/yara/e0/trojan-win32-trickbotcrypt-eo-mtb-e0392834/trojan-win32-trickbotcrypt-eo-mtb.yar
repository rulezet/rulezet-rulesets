rule Trojan_Win32_TrickBotCrypt_EO_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 14 0e 03 df 8a 04 0b 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8d 45 ff 0f af 05 ?? ?? ?? ?? 03 ea 03 c5 8b 6c 24 1c 8a 14 08 8b 44 24 10 8a 1c 28 32 da 8b 54 24 20 88 1c 28 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}