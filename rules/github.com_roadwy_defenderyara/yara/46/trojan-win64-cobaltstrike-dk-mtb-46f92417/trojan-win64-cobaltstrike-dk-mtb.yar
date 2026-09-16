rule Trojan_Win64_CobaltStrike_DK_MTB{
	meta:
		description = "Trojan:Win64/CobaltStrike.DK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0f 28 4c 08 d0 0f 57 c8 0f 28 54 08 e0 0f 57 d0 0f 29 4c 08 d0 0f 29 54 08 e0 0f 28 4c 08 f0 0f 57 c8 0f 28 14 08 0f 57 d0 0f 29 4c 08 f0 0f 29 14 08 48 83 c0 ?? 48 3d [0-05] 75 } 		$a_01_1 = {53 68 65 6c 6c 43 6f 64 65 4c 6f 61 64 65 72 5c 62 69 6e } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}