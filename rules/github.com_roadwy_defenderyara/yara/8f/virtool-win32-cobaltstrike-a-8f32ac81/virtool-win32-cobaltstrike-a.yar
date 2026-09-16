rule VirTool_Win32_CobaltStrike_A{
	meta:
		description = "VirTool:Win32/CobaltStrike.A,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {e8 00 00 00 00 5b 52 45 55 89 e5 81 c3 ?? ?? ?? ?? ff d3 89 c3 57 68 04 00 00 00 50 ff d0 68 f0 b5 a2 56 68 05 00 00 00 50 ff d3 } 		$a_03_1 = {8e 4e 0e ec 74 ?? 81 7d ?? aa fc 0d 7c 74 ?? 81 7d ?? 54 ca af 91 74 } 		$a_01_2 = {0f b7 40 16 25 00 80 00 00 74 09 c7 45 f0 40 00 00 00 eb 07 c7 45 f0 04 00 00 00 } 		$a_01_3 = {ff 75 f0 68 00 30 00 00 8b 45 f4 ff 70 50 6a 00 ff 55 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}