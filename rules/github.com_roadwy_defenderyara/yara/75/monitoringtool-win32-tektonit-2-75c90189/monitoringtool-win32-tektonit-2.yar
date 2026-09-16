rule MonitoringTool_Win32_TektonIt_2{
	meta:
		description = "MonitoringTool:Win32/TektonIt,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {2c 2f 63 20 62 75 69 6c 64 5c 64 61 74 61 2e 65 78 65 20 2d 70 37 4c 33 34 4d 46 38 34 35 4a 4d 48 59 30 20 2d 64 20 43 3a 5c 4c 6f 67 } 		$a_03_1 = {b8 10 80 40 00 a3 ?? ?? ?? ?? b8 30 80 40 00 a3 ?? ?? ?? ?? b8 ?? ?? 40 00 a3 ?? ?? ?? ?? b8 10 14 40 00 a3 ?? ?? ?? ?? a0 60 80 40 00 a2 ?? ?? ?? ?? c3 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}