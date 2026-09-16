rule HackTool_Win32_Mimikatz_gen_H_2{
	meta:
		description = "HackTool:Win32/Mimikatz.gen!H,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {ff 74 24 0c 6a 00 68 10 04 00 00 ff 15 ?? ?? ?? ?? 8b f8 85 ff } 		$a_03_1 = {81 bd fc fe ff ff 4c 48 54 58 75 ?? 8b 45 f4 6a 10 5f 83 c0 34 eb ?? 81 bd fc fe ff ff 53 48 54 58 } 		$a_01_2 = {c6 45 e4 ff c6 45 e5 50 c6 45 e6 10 c6 45 e7 85 c6 45 e8 c0 c6 45 e9 74 c7 45 b4 06 00 00 00 } 		$a_01_3 = {c6 45 e0 8b c6 45 e1 5c c6 45 e2 24 c6 45 e3 18 c6 45 e4 8b c6 45 e5 13 c7 45 d0 06 00 00 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}