rule Trojan_Win32_Lokibot_AU_MTB{
	meta:
		description = "Trojan:Win32/Lokibot.AU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {00 00 5a 80 34 01 ?? 41 39 d1 75 f7 05 ?? ?? 00 00 ff e0 90 0a 30 00 e8 ?? ff ff ff b8 ?? ?? ?? 00 31 c9 68 ?? ?? 00 00 5a } 		$a_03_1 = {53 51 8b d8 54 6a 40 68 ?? ?? 00 00 53 e8 ?? ?? ?? ?? 50 e8 ?? ?? ?? ?? 5a 5b c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}