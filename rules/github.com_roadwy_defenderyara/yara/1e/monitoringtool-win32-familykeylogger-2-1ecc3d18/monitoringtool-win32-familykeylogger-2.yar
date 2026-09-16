rule MonitoringTool_Win32_FamilyKeylogger_2{
	meta:
		description = "MonitoringTool:Win32/FamilyKeylogger,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3c 64 69 76 20 63 6c 61 73 73 3d 22 77 69 6e 74 69 74 6c 65 22 3e 5b 25 30 32 64 2f 25 30 32 64 2f 25 30 34 64 2c 20 25 30 32 64 3a 25 30 32 64 5d 2e 20 20 20 55 73 65 72 3a 20 22 25 73 22 2e 20 20 57 69 6e 64 6f 77 20 74 69 74 6c 65 3a 22 25 73 22 3c 2f 64 69 76 3e } 		$a_03_1 = {63 3a 5c 74 65 6d 70 5c 74 65 6d 70 90 05 02 03 30 2d 39 2e 74 78 74 } 		$a_03_2 = {c7 05 0c 21 01 10 00 00 00 00 68 c0 a1 00 10 8d 8d 90 09 0e 00 80 bd 20 ?? ff ff 0d 75 ?? 83 fb 01 75 ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? fe ff ff 51 ff 15 14 a0 00 10 68 00 02 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}