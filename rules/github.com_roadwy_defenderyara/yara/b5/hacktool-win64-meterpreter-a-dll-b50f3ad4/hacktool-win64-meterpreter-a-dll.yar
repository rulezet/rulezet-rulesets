rule HackTool_Win64_Meterpreter_A_dll{
	meta:
		description = "HackTool:Win64/Meterpreter.A!dll,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_03_0 = {81 f9 5d 68 fa 3c [0-04] 8b } 		$a_01_1 = {81 f9 5b bc 4a 6a 0f 85 } 		$a_03_2 = {8e 4e 0e ec [0-04] aa fc 0d 7c } 		$a_03_3 = {45 33 c9 48 03 da 48 83 ca ff 45 33 c0 e8 ?? ?? ?? ?? ?? 8b } 		$a_03_4 = {ff d3 48 8b c3 48 81 c4 ?? 00 00 00 41 5f 41 5e 41 5d 41 5c 5f 5e 5b 5d c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=5
 
}