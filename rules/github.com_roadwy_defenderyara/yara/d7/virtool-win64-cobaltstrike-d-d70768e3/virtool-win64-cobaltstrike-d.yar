rule VirTool_Win64_CobaltStrike_D{
	meta:
		description = "VirTool:Win64/CobaltStrike.D,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {31 c0 49 89 c9 39 d0 7d 13 48 89 c1 83 e1 03 41 8a 0c 08 41 30 0c 01 48 ff c0 eb e9 4c 89 c9 } 		$a_01_1 = {c7 44 24 48 65 00 00 00 c7 44 24 40 70 00 00 00 c7 44 24 38 69 00 00 00 c7 44 24 30 70 00 00 00 } 		$a_01_2 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4d 53 53 45 2d 25 64 2d 73 65 72 76 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}