rule VirTool_Win64_CobaltStrike_A{
	meta:
		description = "VirTool:Win64/CobaltStrike.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {41 8b 10 41 8b 40 04 4d 8d 40 08 85 d2 75 04 } 		$a_01_1 = {45 8b 0a 41 8b 42 04 4d 8d 52 08 45 85 c9 } 		$a_01_2 = {2b c1 4c 8b c1 44 8b c8 48 8b 0b 8a 43 10 42 30 04 01 49 ff c0 49 ff c9 75 ee } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=4
 
}