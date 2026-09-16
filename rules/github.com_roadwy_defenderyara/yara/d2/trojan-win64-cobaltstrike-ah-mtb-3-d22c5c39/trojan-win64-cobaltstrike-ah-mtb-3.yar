rule Trojan_Win64_CobaltStrike_AH_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {03 c8 48 8b 05 ?? ?? ?? 00 31 0d ?? ?? ?? 00 49 63 48 ?? 41 8b d1 c1 ea 10 88 14 01 } 		$a_03_1 = {48 8b 44 24 ?? 80 e9 ?? 32 0d ?? ?? ?? 00 41 88 0c 02 41 0f b7 44 5e } 		$a_03_2 = {44 03 c9 8b 53 ?? 33 c9 41 81 f0 00 30 00 00 ff 15 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1) >=5
 
}