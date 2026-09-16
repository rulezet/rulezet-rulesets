rule VirTool_Win64_CobaltStrike_A_3{
	meta:
		description = "VirTool:Win64/CobaltStrike.A,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {81 f9 8e 4e 0e ec 74 ?? 81 f9 aa fc 0d 7c 74 ?? 81 f9 54 ca af 91 74 } 		$a_01_1 = {0f b7 45 16 66 23 c1 66 f7 d8 b8 00 40 00 00 45 1b e4 41 83 e4 3c 41 83 c4 04 44 89 64 24 20 66 85 45 16 } 		$a_01_2 = {ff d6 45 33 db 48 85 db 75 21 8b 55 50 45 8b cc 33 c9 41 b8 00 30 00 00 41 ff d5 } 		$a_01_3 = {b9 40 00 00 00 48 03 f3 48 8b c5 f3 a4 b9 40 00 00 00 44 30 00 49 03 c5 49 2b cd } 		$a_01_4 = {48 b8 73 79 73 74 65 6d 33 32 48 83 cb ff 48 89 07 4c 8b c3 49 ff c0 42 80 7c 07 09 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}