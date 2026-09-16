rule VirTool_Win64_Shelesz_A_2{
	meta:
		description = "VirTool:Win64/Shelesz.A,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {48 8b 4d 88 48 8b 01 ff ?? ?? 48 8b 4c 24 70 ?? ?? ?? ?? 48 8b 01 ff ?? ?? 48 8b 45 80 b9 18 00 00 00 4c 8b 30 e8 ?? ?? ?? ?? 48 8b d8 48 85 c0 } 		$a_03_1 = {b8 01 00 00 00 ?? ?? ?? ?? ?? 33 d2 33 c9 ff ?? ?? ?? ?? ?? 85 c0 } 		$a_03_2 = {48 8b 56 20 48 8b 01 ff ?? ?? 48 8b 4d ?? 48 8b 01 ff ?? ?? 48 8b 4d b0 48 8b 01 ff ?? ?? 48 8b 4d b8 48 8b 01 ff } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}