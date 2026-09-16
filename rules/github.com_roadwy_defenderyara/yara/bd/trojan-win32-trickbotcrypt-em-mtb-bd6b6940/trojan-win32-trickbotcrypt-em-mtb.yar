rule Trojan_Win32_TrickBotCrypt_EM_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 04 29 33 d2 8a 14 0e 03 c2 33 d2 f7 35 ?? ?? ?? ?? 2b 15 ?? ?? ?? ?? 8a 04 0a 8a 17 32 d0 8b 44 24 20 43 88 17 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}