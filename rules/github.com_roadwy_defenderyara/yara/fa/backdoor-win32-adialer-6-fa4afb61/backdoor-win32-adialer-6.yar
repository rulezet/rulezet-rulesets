rule Backdoor_Win32_Adialer_6{
	meta:
		description = "Backdoor:Win32/Adialer,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 03 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 c4 f4 ff 75 08 e8 ?? ?? 00 00 89 45 fc 03 45 08 89 45 f8 80 3d ?? ?? 40 00 31 74 24 c6 45 f7 7d eb 18 ff 4d fc ff 4d f8 8b 5d f8 b8 00 00 00 00 8a 03 2a 45 f7 88 03 88 45 f7 83 7d fc 00 75 e2 c9 c2 04 00 55 8b ec 68 } 		$a_01_1 = {54 41 50 49 33 32 2e 44 4c 4c } 		$a_01_2 = {6c 69 6e 65 47 65 74 44 65 76 43 61 70 73 41 } 	condition:
		((#a_02_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2) >=6
 
}