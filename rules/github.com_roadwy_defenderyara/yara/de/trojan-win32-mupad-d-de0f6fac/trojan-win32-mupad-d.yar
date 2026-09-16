rule Trojan_Win32_Mupad_D{
	meta:
		description = "Trojan:Win32/Mupad.D,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_03_0 = {66 89 45 f6 c7 45 e4 00 00 00 00 c7 45 cc 00 00 00 00 8b 4d b4 89 4d b8 ba ?? ?? ?? 00 85 d2 0f 84 ?? ?? 00 00 83 7d b8 00 0f 84 ?? ?? 00 00 b8 ?? ?? ?? 00 85 c0 0f 84 ?? 00 00 00 } 		$a_03_1 = {6a 00 ff 15 ?? ?? 40 00 6a 00 ff 15 ?? ?? 40 00 83 f8 23 74 ?? 8b ?? c8 } 		$a_03_2 = {6a 00 ff 15 ?? ?? 40 00 85 c0 75 10 c7 45 c8 ff ff ff ff b9 40 00 00 00 51 ff 75 c4 ba 00 13 00 00 52 6a 00 b8 00 00 00 00 40 83 7d b8 42 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=2
 
}