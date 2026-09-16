rule VirTool_Win64_Shelcorid_B{
	meta:
		description = "VirTool:Win64/Shelcorid.B,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {6b 00 65 00 48 8b f1 4c 89 7d ?? b9 13 9c bf bd } 		$a_03_1 = {52 74 6c 41 c7 45 ?? 64 64 46 75 c7 45 ?? 6e 63 74 69 c7 45 ?? 6f 6e 54 61 66 c7 ?? ?? 62 6c e8 ?? ?? ?? ?? b9 b5 41 d9 5e 48 8b d8 e8 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}