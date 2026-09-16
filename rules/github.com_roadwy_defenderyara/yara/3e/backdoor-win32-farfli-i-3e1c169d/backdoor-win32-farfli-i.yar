rule Backdoor_Win32_Farfli_I{
	meta:
		description = "Backdoor:Win32/Farfli.I,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8a c2 8b fe 2c ?? 83 c9 ff d0 e0 00 04 32 33 c0 42 f2 ae f7 d1 49 3b d1 72 e6 } 		$a_01_1 = {c6 45 d4 5c c6 45 d5 62 c6 45 d6 65 c6 45 d7 65 c6 45 d8 70 c6 45 d9 2e c6 45 da 73 c6 45 db 79 c6 45 dc 73 } 		$a_03_2 = {33 c0 80 b0 ?? ?? ?? ?? ?? 40 3d ?? ?? ?? ?? 7c f1 33 c0 c3 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*3+(#a_03_2  & 1)*2) >=3
 
}