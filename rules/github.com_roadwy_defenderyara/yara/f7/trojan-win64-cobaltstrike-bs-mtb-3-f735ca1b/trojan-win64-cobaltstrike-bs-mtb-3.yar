rule Trojan_Win64_CobaltStrike_BS_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.BS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {48 8b 44 24 ?? 0f b6 00 0f b6 4c 24 ?? 33 c1 48 8b 8c 24 ?? ?? ?? ?? 48 8b 54 24 ?? 48 2b d1 48 8b ca 0f b6 c9 81 e1 [0-04] 33 c1 48 8b 4c 24 ?? 88 01 48 63 44 24 ?? 48 8b 4c 24 ?? 48 03 c8 48 8b c1 48 89 44 24 ?? e9 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}