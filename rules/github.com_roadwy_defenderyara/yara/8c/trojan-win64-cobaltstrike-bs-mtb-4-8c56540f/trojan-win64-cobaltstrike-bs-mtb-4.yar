rule Trojan_Win64_CobaltStrike_BS_MTB_4{
	meta:
		description = "Trojan:Win64/CobaltStrike.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {44 89 ee 48 c1 ee ?? 42 ?? ?? ?? ?? c1 e3 ?? c1 e1 ?? 09 d9 41 c1 e0 ?? 41 09 c8 41 09 f0 4c 8b b5 ?? ?? ?? ?? 41 0f c8 44 33 85 ?? ?? ?? ?? 48 89 c1 } 		$a_03_1 = {48 39 c6 74 ?? 48 39 c1 0f 84 ?? ?? ?? ?? 8a 1c 07 41 30 1c 06 48 ff c0 eb } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}