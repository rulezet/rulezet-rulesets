rule Trojan_Win32_TrickbotCrypt_SE_MTB{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.SE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c0 83 c9 ff 8b 7d ?? f2 ae f7 d1 49 89 d8 31 d2 f7 f1 8a 04 16 8b 55 ?? 32 04 1a 8b 55 ?? 88 04 1a ff 05 ?? ?? ?? ?? 8b 1d ?? ?? ?? ?? 3b 5d ?? 75 ?? 5b 5e 5f 5d c3 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}