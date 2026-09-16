rule TrojanDropper_Win32_Rootkit_AFH{
	meta:
		description = "TrojanDropper:Win32/Rootkit.AFH,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_01_0 = {83 7c 24 18 02 75 62 b8 cd cc cc cc f7 64 24 2c c1 ea 03 81 fa e8 03 00 00 73 07 ba e8 03 00 00 eb 0d } 		$a_03_1 = {68 80 00 00 00 6a 02 6a 00 6a 01 68 00 00 00 40 51 ff 15 ?? ?? 00 10 8d 54 24 0c 6a 00 52 8b f0 68 00 1a 00 00 68 ?? ?? 00 10 56 c7 44 24 20 00 00 00 00 ff 15 ?? ?? 00 10 } 		$a_00_2 = {62 65 65 70 2e 73 79 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}