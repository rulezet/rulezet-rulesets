rule Trojan_Win64_CobaltStrike_AH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.AH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,5a 00 5a 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 44 24 20 83 c8 ?? 89 44 24 20 48 8d 94 24 80 01 00 00 48 8b 4c 24 38 e8 ?? ?? ?? ?? 0f b6 c0 } 		$a_81_1 = {56 49 52 54 5f 46 49 52 4d 57 41 52 45 3d } 		$a_81_2 = {3b 20 54 70 6d 45 6e 61 62 6c 65 64 3d } 	condition:
		((#a_03_0  & 1)*20+(#a_81_1  & 1)*30+(#a_81_2  & 1)*40) >=90
 
}