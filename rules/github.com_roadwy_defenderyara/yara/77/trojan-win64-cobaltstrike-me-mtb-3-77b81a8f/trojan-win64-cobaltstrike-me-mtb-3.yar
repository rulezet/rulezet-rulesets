rule Trojan_Win64_CobaltStrike_ME_MTB_3{
	meta:
		description = "Trojan:Win64/CobaltStrike.ME!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 33 c4 48 89 44 24 38 33 c9 48 8d 44 24 30 48 89 44 24 28 4c 8d 05 ?? ?? ?? ?? 45 33 c9 89 4c 24 20 33 d2 89 4c 24 30 ff 15 } 		$a_01_1 = {8b 7c 24 48 33 c9 8b d7 41 b8 00 30 00 00 44 8b ff 44 8d 49 04 ff 15 } 		$a_01_2 = {53 74 61 72 74 44 6c 6c 4c 6f 61 64 44 61 74 61 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*5+(#a_01_2  & 1)*5) >=15
 
}