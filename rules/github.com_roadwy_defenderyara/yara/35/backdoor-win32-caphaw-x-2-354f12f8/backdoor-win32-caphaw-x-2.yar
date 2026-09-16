rule Backdoor_Win32_Caphaw_X_2{
	meta:
		description = "Backdoor:Win32/Caphaw.X,SIGNATURE_TYPE_PEHSTR_EXT,04 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 4c 24 04 85 c9 89 44 24 08 db 44 24 08 d9 fa db 44 24 04 7d 06 dc 05 ?? ?? ?? ?? de c1 e8 ?? ?? 00 00 89 44 24 04 8b 14 24 42 89 14 24 81 3c 24 00 00 ?? 01 72 c4 } 		$a_03_1 = {85 c0 75 13 8b 45 ?? 8b 48 3c 03 c8 51 50 53 e8 ?? ?? ff ff 83 c4 0c 90 09 1c 00 8b 46 3c 8b 4c ?? 54 8b d1 c1 e9 02 8b fb f3 a5 8b ca 83 e1 03 f3 a4 e8 ?? ?? ff ff } 		$a_03_2 = {8b 53 3c 8b ?? ?? 28 03 ?? 83 c4 04 89 ?? ?? ff } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}