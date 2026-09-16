rule HackTool_Win64_Meterpreter_A_dll_5{
	meta:
		description = "HackTool:Win64/Meterpreter.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 07 00 00 "
		
	strings :
		$a_01_0 = {81 f9 5b bc 4a 6a 0f 85 } 		$a_03_1 = {81 f9 5d 68 fa 3c 0f 85 ?? 00 00 00 } 		$a_01_2 = {b8 0a 4c 53 75 } 		$a_03_3 = {8e 4e 0e ec 74 [0-05] aa fc 0d 7c 74 [0-05] 54 ca af 91 74 [0-05] 1b c6 46 79 [0-05] f2 32 f6 0e 75 } 		$a_03_4 = {3c 45 8b cb 33 c9 ?? 03 ?? 41 b8 00 30 00 00 [0-10] ff d6 } 		$a_03_5 = {3c 33 c9 41 b8 00 30 00 00 ?? 03 ?? 44 8d 49 [0-10] ff d6 } 		$a_03_6 = {8b 5f 28 45 33 c0 33 d2 48 83 c9 ff ?? 03 ?? ff 94 24 88 00 00 00 45 33 c0 ?? 8b ?? 41 8d ?? ?? ff d3 48 8b c3 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*2+(#a_03_5  & 1)*2+(#a_03_6  & 1)*1) >=7
 
}