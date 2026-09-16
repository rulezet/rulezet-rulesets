rule HackTool_Win64_Meterpreter_A_dll_2{
	meta:
		description = "HackTool:Win64/Meterpreter.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 07 00 00 "
		
	strings :
		$a_01_0 = {00 52 65 66 6c 65 63 74 69 76 65 4c 6f 61 64 65 72 00 } 		$a_01_1 = {81 f9 5b bc 4a 6a 0f 85 } 		$a_03_2 = {8e 4e 0e ec 74 [0-04] aa fc 0d 7c 74 [0-04] 54 ca af 91 74 [0-04] f2 32 f6 0e 75 } 		$a_03_3 = {81 f9 5d 68 fa 3c 0f 85 ?? 00 00 00 } 		$a_01_4 = {b8 0a 4c 53 75 } 		$a_03_5 = {3c 33 c9 41 b8 00 30 00 00 ?? 03 ?? 44 8d 49 40 [0-04] ff d6 } 		$a_01_6 = {41 8b 5f 28 45 33 c0 33 d2 48 83 c9 ff 49 03 de ff 54 24 68 45 33 c0 49 8b ce 41 8d 50 01 ff d3 48 8b c3 48 83 c4 40 41 5f 41 5e 5b c3 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_01_4  & 1)*1+(#a_03_5  & 1)*1+(#a_01_6  & 1)*1) >=6
 
}