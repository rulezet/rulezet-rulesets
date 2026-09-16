rule HackTool_Win32_Meterpreter_A_dll_4{
	meta:
		description = "HackTool:Win32/Meterpreter.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {75 e3 81 f9 5b bc 4a 6a 0f 85 } 		$a_03_1 = {81 f9 5d 68 fa 3c 75 ?? 8b } 		$a_03_2 = {b8 0a 4c 53 75 21 8b 45 ?? 0f b7 } 		$a_03_3 = {8e 4e 0e ec 74 [0-03] aa fc 0d 7c 74 [0-03] 54 ca af 91 74 [0-03] 1b c6 46 79 74 [0-03] f2 32 f6 0e 75 } 		$a_01_4 = {64 a1 30 00 00 00 6a 04 89 75 f8 c7 45 d4 02 00 00 00 8b 40 0c c7 45 c8 01 00 00 00 8b 58 14 89 5d ec 58 85 db } 		$a_01_5 = {8b 77 28 33 ff 57 57 6a ff 03 f3 ff 55 d8 33 c0 57 40 50 53 ff d6 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}