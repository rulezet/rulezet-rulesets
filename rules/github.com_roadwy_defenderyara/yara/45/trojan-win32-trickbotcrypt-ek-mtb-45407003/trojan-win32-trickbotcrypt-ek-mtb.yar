rule Trojan_Win32_TrickBotCrypt_EK_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 55 ff 83 ea 69 88 55 ff 6a 12 e8 ?? ?? ?? ?? 83 c4 04 0f b6 45 ff 0f b6 4d fe 0b c8 88 4d fe 68 0a 01 00 00 e8 ?? ?? ?? ?? 83 c4 04 0f b6 55 fd 0f b6 45 fe 33 c2 88 45 fe 68 12 01 00 00 e8 ?? ?? ?? ?? 83 c4 04 8a 4d fd 80 c1 01 88 4d fd 6a 4a e8 ?? ?? ?? ?? 83 c4 04 8b 55 f4 8a 45 fe 88 02 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}