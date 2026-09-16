rule HackTool_Win64_Mimikatz_gen_G{
	meta:
		description = "HackTool:Win64/Mimikatz.gen!G,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 01 00 c0 0f 84 ?? ?? ?? ?? 81 ?? 4b 00 00 c0 0f 84 [0-40] e9 ?? 00 00 00 81 ?? 4b 00 00 c0 0f 84 [0-40] ba ff ff 00 00 } 		$a_03_1 = {01 00 00 c0 48 85 c9 0f 84 [0-60] 0f b7 03 83 f8 21 74 1a 83 f8 2a 74 0a 48 8b cb e8 ?? 00 00 00 eb } 		$a_03_2 = {48 8b da 83 f9 03 75 [0-40] 45 33 c9 45 33 c0 33 d2 b9 85 04 00 00 ff 15 ?? ?? ?? ?? 33 c0 48 83 c4 20 5b c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}