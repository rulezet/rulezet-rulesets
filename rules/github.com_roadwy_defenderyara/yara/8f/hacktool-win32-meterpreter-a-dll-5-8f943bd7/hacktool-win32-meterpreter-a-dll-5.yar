rule HackTool_Win32_Meterpreter_A_dll_5{
	meta:
		description = "HackTool:Win32/Meterpreter.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {5f 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 40 } 		$a_01_1 = {75 e3 81 f9 5b bc 4a 6a 0f 85 } 		$a_03_2 = {8e 4e 0e ec 74 [0-03] aa fc 0d 7c 74 [0-03] 54 ca af 91 74 [0-03] f2 32 f6 0e 75 } 		$a_03_3 = {81 f9 5d 68 fa 3c 75 ?? 8b } 		$a_03_4 = {b8 0a 4c 53 75 21 8b 45 ?? 0f b7 } 		$a_01_5 = {8b 5e 3c 6a 40 03 de 68 00 30 00 00 89 5d f0 ff 73 50 6a 00 ff } 		$a_01_6 = {8b 5d f0 8b 73 28 33 db 53 53 6a ff 03 f7 ff 55 dc 33 c0 53 40 50 57 ff d6 5f 8b c6 5e 5b 8b e5 5d c3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}