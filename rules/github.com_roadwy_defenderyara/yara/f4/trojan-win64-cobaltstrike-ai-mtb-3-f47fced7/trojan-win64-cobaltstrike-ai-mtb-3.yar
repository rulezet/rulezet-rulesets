rule Trojan_Win64_CobaltStrike_AI_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 39 44 24 ?? 44 89 c0 76 ?? 99 f7 f9 48 8d 05 ?? ?? ?? ?? 48 63 d2 8a 14 10 48 8b 84 24 ?? ?? ?? ?? 42 32 14 00 42 88 14 06 49 ff c0 eb } 		$a_00_1 = {65 48 8b 04 25 60 00 00 00 48 8b 40 18 48 89 cf 48 8b 58 10 48 89 de 48 8b 4b 60 48 89 fa } 	condition:
		((#a_03_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}