rule Trojan_Win32_TrickBotCrypt_EQ_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {45 33 c9 45 33 c0 ba 04 10 00 00 48 8b 49 40 ff 15 ?? ?? ?? ?? 44 3b f8 0f 8d ?? ?? ?? ?? 3d 01 00 00 8a 06 52 46 30 07 5a 4a 47 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}