rule TrojanDropper_Win32_Sirefef_B_3{
	meta:
		description = "TrojanDropper:Win32/Sirefef.B,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 08 00 00 "
		
	strings :
		$a_03_0 = {8b f8 3b fe 74 42 53 68 ?? ?? ?? ?? 6a fc 57 ff 15 ?? ?? ?? ?? 6a 01 57 } 		$a_01_1 = {83 7d 0c 18 } 		$a_01_2 = {8b c4 53 6a 20 83 c0 f0 50 ff 15 } 		$a_01_3 = {8b dc 8d 47 60 50 6a 20 83 c3 f0 53 ff 15 } 		$a_01_4 = {8b fc 8d 43 60 50 6a 20 83 c7 f0 57 ff 15 } 		$a_01_5 = {8b f4 8d 47 60 50 6a 20 83 c6 f0 56 ff 15 } 		$a_01_6 = {8d 48 28 8b 40 14 c1 e8 02 8b 54 24 08 31 11 83 c1 04 48 75 f4 } 		$a_03_7 = {8b 48 fc 83 c0 28 4a f3 a4 75 ea 33 c0 8d bd ?? ?? ?? ?? b9 ?? ?? ?? ?? f3 ab c7 85 ?? ?? ?? ?? 10 00 01 00 c7 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*5+(#a_03_7  & 1)*7) >=7
 
}