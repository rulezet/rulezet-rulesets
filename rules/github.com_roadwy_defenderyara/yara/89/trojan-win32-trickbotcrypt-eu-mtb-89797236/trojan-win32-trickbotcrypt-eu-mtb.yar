rule Trojan_Win32_TrickBotCrypt_EU_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 45 f4 8a 04 30 34 e0 88 45 0f 8b de 85 f6 ?? ?? e8 ?? ?? ?? ?? 8b 4d 08 8a 45 0f 3b 75 fc ?? ?? 8a d3 2a d1 80 e2 e0 32 13 32 d0 88 13 03 df 3b 5d fc ?? ?? 46 ff 4d f8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}