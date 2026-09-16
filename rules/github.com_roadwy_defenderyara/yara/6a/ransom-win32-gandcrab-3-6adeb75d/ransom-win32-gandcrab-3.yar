rule Ransom_Win32_GandCrab_3{
	meta:
		description = "Ransom:Win32/GandCrab,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8b 45 08 8d 34 07 e8 7d ff ff ff 30 06 47 3b 7d 0c 7c ed } 		$a_02_1 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? 41 00 3d fe 44 05 00 75 1f 8d 85 fc fb ff ff 50 ff 15 ?? ?? 41 00 6a 00 68 ?? ?? 41 00 68 ?? ?? 41 00 ff 15 ?? ?? 41 00 0f b7 05 ?? ?? 41 00 8b 4d fc 33 cd 25 ff 7f 00 00 90 09 05 00 a1 ?? ?? 41 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}