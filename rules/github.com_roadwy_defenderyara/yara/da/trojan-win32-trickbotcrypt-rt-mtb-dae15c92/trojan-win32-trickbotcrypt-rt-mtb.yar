rule Trojan_Win32_TrickBotCrypt_RT_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e2 8b 75 ?? 89 30 8b 45 ?? 89 01 8b 4d ?? 89 0a c7 45 ?? eb e9 1d dd e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}