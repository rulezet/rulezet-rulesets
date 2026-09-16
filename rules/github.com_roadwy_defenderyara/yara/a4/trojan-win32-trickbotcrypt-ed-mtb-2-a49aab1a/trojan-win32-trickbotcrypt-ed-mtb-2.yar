rule Trojan_Win32_TrickBotCrypt_ED_MTB_2{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 14 0f 89 44 24 10 0f b6 04 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? b8 02 00 00 00 2b 05 ?? ?? ?? ?? 45 0f af c3 0f af c3 48 03 15 ?? ?? ?? ?? 0f af c3 03 c2 8a 14 08 8b 44 24 10 30 10 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}