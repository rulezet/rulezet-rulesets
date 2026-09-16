rule VirTool_Win64_CobaltStrike_A_2{
	meta:
		description = "VirTool:Win64/CobaltStrike.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {f0 e8 c8 00 00 00 41 51 41 50 52 51 56 48 31 d2 65 48 8b 52 60 48 8b 52 18 48 8b 52 20 48 8b 72 50 48 0f b7 4a 4a } 		$a_01_1 = {e9 4f ff ff ff 5d 6a 00 49 be 77 69 6e 69 6e 65 74 00 41 56 49 89 e6 4c 89 f1 41 ba 4c 77 26 07 ff d5 48 31 c9 48 31 d2 4d 31 c0 4d 31 c9 41 50 41 50 41 ba 3a 56 79 a7 ff d5 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}