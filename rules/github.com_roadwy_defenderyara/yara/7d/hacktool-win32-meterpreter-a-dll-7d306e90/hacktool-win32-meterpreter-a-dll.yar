rule HackTool_Win32_Meterpreter_A_dll{
	meta:
		description = "HackTool:Win32/Meterpreter.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_03_0 = {8e 4e 0e ec [0-04] aa fc 0d 7c } 		$a_03_1 = {81 f9 5d 68 fa 3c [0-04] 8b } 		$a_01_2 = {81 f9 5b bc 4a 6a 0f 85 } 		$a_03_3 = {8b 46 ec 89 45 f4 85 c0 ?? ?? ?? ?? ?? 50 ?? ?? ?? ?? 50 ?? ?? ?? 50 ?? ?? ?? 6a ff 50 e8 ?? ?? ?? ?? 8b ?? f8 83 c4 18 83 c6 28 85 ff 0f 85 ?? ?? ?? ?? 8b 5d ec } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1) >=4
 
}