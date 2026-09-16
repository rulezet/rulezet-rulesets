rule HackTool_Win32_Meterpreter_A_dll_2{
	meta:
		description = "HackTool:Win32/Meterpreter.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 06 00 00 "
		
	strings :
		$a_03_0 = {8e 4e 0e ec [0-25] aa fc 0d 7c } 		$a_03_1 = {5d 68 fa 3c [0-04] 8b } 		$a_01_2 = {5b bc 4a 6a 0f 85 } 		$a_03_3 = {45 08 50 8d ?? ?? 50 ?? ?? ?? 6a ff 50 e8 ?? ?? ?? ?? 83 c4 18 } 		$a_01_4 = {53 61 6d 49 46 72 65 65 5f 53 41 4d 50 52 5f 55 53 45 52 5f 49 4e 46 4f 5f 42 55 46 46 45 52 } 		$a_01_5 = {53 61 6d 49 46 72 65 65 5f 53 41 4d 50 52 5f 45 4e 55 4d 45 52 41 54 49 4f 4e 5f 42 55 46 46 45 52 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*2+(#a_03_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=8
 
}