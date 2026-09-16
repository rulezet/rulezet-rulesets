rule Trojan_Win64_CobaltStrike_PH_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.PH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {43 33 1c 87 45 89 e0 41 c1 ec 08 45 0f b6 e4 47 0f b6 24 23 4c 8d 3d 28 48 1a 00 43 33 1c a7 45 0f b6 c0 47 0f b6 04 18 4c 8d 25 14 4c 1a 00 43 33 1c 84 } 		$a_01_1 = {43 89 1c 81 48 ff c2 66 0f 1f 44 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}