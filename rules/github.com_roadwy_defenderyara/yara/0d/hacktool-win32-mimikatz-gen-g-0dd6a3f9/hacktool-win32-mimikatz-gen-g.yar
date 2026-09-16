rule HackTool_Win32_Mimikatz_gen_G{
	meta:
		description = "HackTool:Win32/Mimikatz.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 01 00 c0 [0-20] 81 fe 4b 00 00 c0 [0-40] 81 fe 4b 00 00 c0 [0-30] 68 ff ff 00 00 50 } 		$a_03_1 = {01 00 00 c0 85 ?? 74 [0-50] 0f b7 06 83 f8 21 74 ?? 83 f8 2a 74 [0-04] e8 ?? 00 00 00 eb } 		$a_03_2 = {83 7c 24 04 03 75 [0-30] 59 59 85 c0 75 10 33 c0 50 50 50 68 85 04 00 00 ff 15 [0-08] 33 c0 c2 08 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}