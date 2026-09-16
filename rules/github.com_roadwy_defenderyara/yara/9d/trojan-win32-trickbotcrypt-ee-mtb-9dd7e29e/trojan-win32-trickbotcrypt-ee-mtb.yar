rule Trojan_Win32_TrickBotCrypt_EE_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 08 03 45 f8 0f b6 08 89 4d f4 8b 55 08 03 55 f8 0f b6 02 2b 45 fc 89 45 fc 79 ?? 8b 4d fc 81 c1 00 01 00 00 89 4d fc 8b 55 08 03 55 f8 8a 45 fc 88 02 eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}