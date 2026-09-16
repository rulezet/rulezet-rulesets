rule Trojan_Win32_TrickBotCrypt_EA_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 08 0f b6 55 ?? 33 ca 8b 45 ?? 2b 45 ?? 0f b6 d0 81 e2 ff 00 00 00 33 ca 8b 45 ?? 88 08 8b 4d ?? 03 4d ?? 89 4d ?? eb } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}