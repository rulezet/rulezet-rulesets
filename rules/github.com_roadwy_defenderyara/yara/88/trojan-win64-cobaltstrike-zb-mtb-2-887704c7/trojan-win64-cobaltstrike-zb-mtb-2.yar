rule Trojan_Win64_CobaltStrike_ZB_MTB_2{
	meta:
		description = "Trojan:Win64/CobaltStrike.ZB!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {48 98 33 d2 b9 3e 00 00 00 48 f7 f1 48 8b c2 89 44 24 24 48 63 44 24 24 } 		$a_01_1 = {8b 44 24 28 ff c0 89 44 24 28 48 8b 44 24 30 8b 00 48 8b 4c 24 30 48 03 c8 48 8b c1 48 89 44 24 30 48 8b 44 24 30 83 38 00 75 99 41 b8 00 80 00 00 33 d2 48 8b 4c 24 30 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}