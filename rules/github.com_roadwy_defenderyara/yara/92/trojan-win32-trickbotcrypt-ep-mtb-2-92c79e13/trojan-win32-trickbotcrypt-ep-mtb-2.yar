rule Trojan_Win32_TrickBotCrypt_EP_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b c3 0f af c7 8d 04 58 2b 05 ?? ?? ?? ?? 03 45 f8 03 c2 8b 55 f4 0f b6 14 32 89 45 f0 8b 45 fc 0f b6 04 30 03 c2 33 d2 f7 35 ?? ?? ?? ?? 8b 45 f0 41 0f af cf 2b d1 03 d3 8a 0c 32 30 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}