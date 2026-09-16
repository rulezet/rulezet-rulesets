rule Trojan_Win64_CobaltStrike_AB_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_81_0 = {47 6f 20 62 75 69 6c 64 20 49 44 3a } 		$a_81_1 = {54 63 79 41 6b 71 68 34 6f 4a 58 67 56 33 57 59 79 4c 34 4b 45 66 43 4d 6b 39 57 38 6f 4a 43 70 6d 78 31 62 6f 2b 6a 56 67 4b 59 3d } 		$a_81_2 = {51 4a 4d 62 68 43 53 45 48 35 72 41 75 52 78 68 2b 43 74 57 39 36 67 30 4f 72 30 46 78 61 39 49 4b 72 34 75 63 3d } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=3
 
}