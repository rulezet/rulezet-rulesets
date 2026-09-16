rule Trojan_Win32_TrickbotCrypt_SV_MTB{
	meta:
		description = "Trojan:Win32/TrickbotCrypt.SV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {53 57 56 b8 ?? 00 00 00 89 44 24 ?? b9 ?? ?? ?? ?? 89 4c 24 ?? b8 ?? 00 00 00 89 44 24 ?? 8d 15 ?? ?? ?? ?? 89 14 24 e8 ?? ?? ?? ?? 83 c4 ?? 33 c0 c3 } 		$a_03_1 = {53 56 8b 4c 24 ?? 8b 54 24 ?? 8b 74 24 ?? 8b 7c 24 ?? 85 d2 74 ?? ac 52 30 07 5a 4a 47 e2 ?? 5e 5b 33 c0 c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}