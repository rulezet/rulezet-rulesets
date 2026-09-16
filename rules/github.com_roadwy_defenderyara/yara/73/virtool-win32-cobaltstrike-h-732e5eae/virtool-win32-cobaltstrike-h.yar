rule VirTool_Win32_CobaltStrike_H{
	meta:
		description = "VirTool:Win32/CobaltStrike.H,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8b 5d 08 8b 75 0c 8b 55 10 39 f0 7d 0e 89 c1 83 e1 03 8a 0c 0a 30 0c 03 40 eb ee 89 1c 24 } 		$a_01_1 = {c7 44 24 24 65 00 00 00 c7 44 24 20 70 00 00 00 c7 44 24 1c 69 00 00 00 c7 44 24 18 70 00 00 00 } 		$a_01_2 = {25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 25 63 4d 53 53 45 2d 25 64 2d 73 65 72 76 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}