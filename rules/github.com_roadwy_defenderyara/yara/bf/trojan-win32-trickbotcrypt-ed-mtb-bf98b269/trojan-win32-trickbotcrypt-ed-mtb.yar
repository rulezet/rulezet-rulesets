rule Trojan_Win32_TrickBotCrypt_ED_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 54 24 14 03 d0 a0 ?? ?? ?? ?? f6 eb 2a c8 8a c1 b1 1f f6 e9 8b 4c 24 ?? 02 04 31 2a 05 ?? ?? ?? ?? 30 02 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}