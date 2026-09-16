rule Trojan_Win32_TrickbotCrypt_SQ_MTB{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 d2 8d 41 ?? f7 f7 6a 00 8b f2 33 d2 89 75 ?? 6a 00 0f b6 04 1e 03 45 ?? f7 f7 0f b6 04 1e 89 55 ?? 8a 0c 1a 88 04 1a 88 0c 1e 0f b6 c1 0f b6 0c 1a 33 d2 03 c1 f7 f7 8b f2 ff 15 ?? ?? ?? ?? 8b 4d ?? 8b 55 ?? 0f b6 04 0a 32 04 1e 88 01 41 ff 4d ?? 89 4d } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}