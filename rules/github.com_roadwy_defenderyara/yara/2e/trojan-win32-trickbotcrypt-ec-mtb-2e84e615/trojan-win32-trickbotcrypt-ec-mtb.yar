rule Trojan_Win32_TrickBotCrypt_EC_MTB{
	meta:
		description = "Trojan:Win32/TrickBotCrypt.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {f6 eb 8a 0c 31 2a c8 a0 ?? ?? ?? ?? f6 eb 8a 1d ?? ?? ?? ?? 02 c8 8a 45 00 2a cb 32 c1 42 88 45 00 90 09 0b 00 a0 ?? ?? ?? ?? f6 2d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}