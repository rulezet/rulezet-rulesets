rule Trojan_Win32_Mupad_E_2{
	meta:
		description = "Trojan:Win32/Mupad.E,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 00 6a 00 e8 ?? 04 00 00 dd d8 83 c4 08 6a 00 6a 00 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? 40 00 } 		$a_03_1 = {6a 00 ff 15 ?? ?? 40 00 83 f8 23 74 08 6a 00 ff 15 ?? ?? 40 00 8b [0-01] c8 [0-08] 00 6a 00 ff 15 ?? ?? 40 00 } 		$a_03_2 = {c7 45 c8 ff ff ff ff b9 40 00 00 00 51 ff 75 c4 b9 70 13 00 00 51 b9 00 00 00 00 51 83 7d b8 42 74 ?? ff 15 ?? ?? 40 00 } 		$a_03_3 = {6a 0a ff 15 ?? ?? 40 00 6a 00 ff 15 ?? ?? 40 00 85 c0 75 1c 8b [0-04] 40 00 89 ?? b8 8b ?? b8 ff d1 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}