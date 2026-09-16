rule VirTool_Win64_Shelesz_A_3{
	meta:
		description = "VirTool:Win64/Shelesz.A,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {55 48 89 e5 48 81 ec e8 00 00 00 48 89 84 24 f8 00 00 00 48 89 9c 24 00 01 00 00 ?? ba 01 00 00 00 f0 0f c1 50 38 ff c2 85 d2 ?? ?? 48 83 c0 34 31 db 31 c9 e8 ?? ?? ?? ?? 48 8b } 		$a_01_1 = {55 48 89 e5 48 81 ec b8 00 00 00 66 44 0f d6 bc 24 b0 00 00 00 48 89 84 24 c8 00 00 00 48 89 9c 24 d0 00 00 00 c6 44 24 3f 00 44 0f 11 7c 24 40 84 00 48 83 c0 28 48 89 44 24 58 e8 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}