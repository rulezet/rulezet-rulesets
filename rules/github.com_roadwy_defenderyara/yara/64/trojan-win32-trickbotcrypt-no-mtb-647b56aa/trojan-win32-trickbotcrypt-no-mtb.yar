rule Trojan_Win32_TrickbotCrypt_NO_MTB{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.NO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8a 04 0f 81 e2 ff 00 00 00 03 c2 33 d2 f7 35 ?? ?? ?? ?? a1 ?? ?? ?? ?? 8b 00 8b ea 8b 54 24 ?? 8a 14 10 32 14 29 8b 6c 24 ?? 88 14 28 a1 ?? ?? ?? ?? 40 3b c3 a3 ?? ?? ?? ?? 72 } 		$a_03_1 = {33 d2 8a 14 ?? 8b c3 25 ff 00 00 00 03 ea 03 c5 33 d2 f7 35 ?? ?? ?? ?? 46 47 8b ea 8a 04 29 88 1c 29 88 47 ?? a1 ?? ?? ?? ?? 3b f0 72 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}