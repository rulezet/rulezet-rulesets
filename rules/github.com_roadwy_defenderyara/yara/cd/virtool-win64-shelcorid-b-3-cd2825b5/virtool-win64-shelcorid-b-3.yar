rule VirTool_Win64_Shelcorid_B_3{
	meta:
		description = "VirTool:Win64/Shelcorid.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 59 [0-40] c7 44 24 ?? ?? 00 00 00 e8 ?? 00 00 00 48 89 f4 } 		$a_01_1 = {b9 13 9c bf bd } 		$a_01_2 = {b9 b5 41 d9 5e } 		$a_01_3 = {b9 49 f7 02 78 } 		$a_01_4 = {b9 58 a4 53 e5 } 		$a_01_5 = {b9 10 e1 8a c3 } 		$a_01_6 = {b9 af b1 5c 94 } 		$a_01_7 = {b9 33 00 9e 95 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=7
 
}