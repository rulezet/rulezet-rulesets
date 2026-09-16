rule Trojan_Win64_CobaltStrike_BMD_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.BMD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_03_0 = {48 33 c4 48 89 44 24 ?? 4d 8b e0 4c 8b fa 48 8b d9 45 33 ed 45 33 c0 44 89 6c 24 ?? ba } 		$a_01_1 = {6d 73 73 74 75 64 79 5c 7a 68 69 7a 68 65 6e 5c 74 75 66 61 71 69 78 69 61 6e 67 5c 78 36 34 5c 52 65 6c 65 61 73 65 5c 74 75 66 61 71 69 78 69 61 6e 67 2e 70 64 62 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}