rule Trojan_Win64_CobaltStrike_CE_MTB_6{
	meta:
		description = "Trojan:Win64/CobaltStrike.CE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,10 00 10 00 03 00 00 "
		
	strings :
		$a_00_0 = {0f b6 07 4c 8d 44 24 68 48 8b 54 24 60 34 45 4c 63 f6 41 b9 01 00 00 00 49 03 d6 88 44 24 68 49 8b cf 4c 89 64 24 20 } 		$a_81_1 = {42 79 70 61 73 73 5f 41 56 2e 70 64 62 } 		$a_81_2 = {66 75 63 6b 20 73 61 6e 64 62 6f 78 } 	condition:
		((#a_00_0  & 1)*10+(#a_81_1  & 1)*3+(#a_81_2  & 1)*3) >=16
 
}