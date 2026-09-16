rule Trojan_Win32_TrickBotCrypt_EV_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 0e 0f b6 04 0f 03 c2 33 d2 bb 05 18 00 00 f7 f3 a1 ?? ?? ?? ?? 03 55 e0 8d 14 42 03 55 dc 8b 45 f8 03 15 ?? ?? ?? ?? 40 03 15 ?? ?? ?? ?? 89 45 f8 8a 1c 0a 8b 55 fc 30 5c 02 ff } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}