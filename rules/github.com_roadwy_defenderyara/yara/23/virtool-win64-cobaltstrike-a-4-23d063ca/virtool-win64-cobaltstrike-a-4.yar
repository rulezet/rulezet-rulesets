rule VirTool_Win64_CobaltStrike_A_4{
	meta:
		description = "VirTool:Win64/CobaltStrike.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {4d 5a 41 52 55 48 89 e5 48 81 ec 20 00 00 00 48 8d 1d ea ff ff ff 48 89 df 48 81 c3 ?? ?? ?? ?? ff d3 41 b8 f0 b5 a2 56 68 04 00 00 00 5a 48 89 f9 ff d0 } 		$a_03_1 = {81 f9 8e 4e 0e ec 74 ?? 81 f9 aa fc 0d 7c 74 ?? 81 f9 54 ca af 91 74 } 		$a_01_2 = {0f b7 45 16 66 23 c1 66 f7 d8 b8 00 40 00 00 45 1b e4 41 83 e4 3c 41 83 c4 04 44 89 64 24 20 66 85 45 16 } 		$a_01_3 = {ff d6 45 33 db 48 85 db 75 21 8b 55 50 45 8b cc 33 c9 41 b8 00 30 00 00 41 ff d5 } 		$a_01_4 = {b9 40 00 00 00 48 03 f3 48 8b c5 f3 a4 b9 40 00 00 00 44 30 00 49 03 c5 49 2b cd } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}