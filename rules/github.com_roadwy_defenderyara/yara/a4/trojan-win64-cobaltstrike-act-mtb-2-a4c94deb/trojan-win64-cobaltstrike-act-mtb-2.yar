rule Trojan_Win64_CobaltStrike_ACT_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.ACT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {89 c2 48 8b 45 10 48 01 d0 0f b7 00 66 89 45 f6 0f b7 45 f6 8b 55 f8 c1 ca 08 01 d0 31 45 f8 8b 45 fc 48 8b 55 10 48 01 d0 0f b6 00 84 c0 } 		$a_01_1 = {c6 85 35 02 00 00 74 c6 85 36 02 00 00 63 c6 85 37 02 00 00 65 c6 85 38 02 00 00 74 c6 85 39 02 00 00 6f c6 85 3a 02 00 00 72 c6 85 3b 02 00 00 50 c6 85 3c 02 00 00 6c c6 85 3d 02 00 00 61 c6 85 3e 02 00 00 75 c6 85 3f 02 00 00 74 c6 85 40 02 00 00 72 c6 85 41 02 00 00 69 c6 85 42 02 00 00 56 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}