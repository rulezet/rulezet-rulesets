rule HackTool_Win64_Meterpreter_A_dll_4{
	meta:
		description = "HackTool:Win64/Meterpreter.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_03_0 = {5d 68 fa 3c [0-04] 8b } 		$a_01_1 = {5b bc 4a 6a 0f 85 } 		$a_01_2 = {48 0f b6 02 8b 4a 01 48 8b 52 05 41 88 02 41 89 4a 01 49 89 52 05 49 8b c3 c3 } 		$a_01_3 = {48 0f b7 02 8b 4a 02 48 8b 52 06 66 41 89 02 41 89 4a 02 49 89 52 06 49 8b c3 c3 } 		$a_03_4 = {48 8b 04 0a 4c 8b 54 0a 08 48 83 c1 [0-01] 48 89 41 e0 4c 89 51 e8 48 8b 44 0a f0 4c 8b 54 0a f8 49 ff c9 48 89 41 f0 4c 89 51 f8 75 d4 } 		$a_03_5 = {48 8b d8 48 85 c0 0f 84 ?? ?? ?? ?? 48 8b d0 8b 0d ?? ?? ?? ?? e8 ?? ?? ?? ?? 48 8b cb 85 c0 74 16 33 d2 e8 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 89 03 48 83 4b 08 ff } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_03_4  & 1)*1+(#a_03_5  & 1)*1) >=6
 
}