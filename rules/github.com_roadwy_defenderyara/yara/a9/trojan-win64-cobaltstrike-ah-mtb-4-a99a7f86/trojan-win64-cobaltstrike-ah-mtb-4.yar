rule Trojan_Win64_CobaltStrike_AH_MTB_4{
	meta:
		description = "Trojan:Win64/CobaltStrike.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {48 89 c2 49 89 f0 e8 ?? ?? ?? ?? 48 8d 15 ?? ?? ?? ?? 48 89 f9 e8 ?? ?? ?? ?? 48 c7 44 24 20 ?? ?? ?? ?? 41 b9 ?? ?? ?? ?? 48 c7 c1 } 		$a_80_1 = {45 74 77 45 76 65 6e 74 57 72 69 74 65 46 75 6c 6c } 		$a_80_2 = {6e 6f 74 65 70 61 64 2e 65 78 65 } 		$a_80_3 = {57 72 69 74 65 50 72 6f 63 65 73 73 4d 65 6d 6f 72 79 } 	condition:
		((#a_03_0  & 1)*5+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=8
 
}