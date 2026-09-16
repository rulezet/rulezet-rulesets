rule Trojan_Win64_CobaltStrike_BP_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {89 f8 80 3c 06 ?? 74 ?? 0f b7 04 06 89 da 48 89 e9 ff c7 c1 ca ?? 01 d0 31 c3 e8 ?? ?? ?? ?? eb } 		$a_03_1 = {48 89 c2 48 8b 4c 24 ?? 83 e2 ?? 41 8a 54 15 ?? 32 14 07 88 14 01 48 ff c0 eb } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}