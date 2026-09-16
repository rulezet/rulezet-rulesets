rule VirTool_Win64_CobaltStrike_I{
	meta:
		description = "VirTool:Win64/CobaltStrike.I,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {b9 60 ea 00 00 ff d3 eb f7 [0-10] 48 ff e1 } 		$a_03_1 = {41 b8 00 30 00 00 31 c9 48 89 f7 ff 15 ?? ?? ?? ?? 48 89 c3 31 c0 39 f8 7d ?? 48 89 c2 83 e2 03 } 		$a_03_2 = {4c 8d 4c 24 3c 48 89 f2 48 89 d9 41 b8 20 00 00 00 ff 15 ?? ?? ?? ?? 4c 8d ?? ?? ff ff ff 49 89 d9 31 d2 31 c9 48 c7 44 24 28 00 00 00 00 c7 44 24 20 00 00 00 00 ff 15 ?? ?? ?? ?? 90 90 48 83 c4 40 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}