rule Adware_Win32_Eorezo_5{
	meta:
		description = "Adware:Win32/Eorezo,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {51 c7 04 24 ?? 00 00 00 e8 ?? ?? ?? ?? 85 c0 74 09 8b 04 24 83 c0 ?? 89 04 24 8b 0c 24 ff 14 8d ?? ?? ?? ?? 33 c0 59 c3 } 		$a_03_1 = {8a 10 33 c9 83 c0 02 84 d2 0f 84 ?? 00 00 00 8d 9b 00 00 00 00 0f b6 d2 03 ca 8b d1 c1 ea ?? c1 e1 ?? 0b d1 81 f2 ?? ?? ?? ?? 8b ca 8a 10 83 c0 02 84 d2 75 e0 81 f9 ?? ?? ?? ?? 74 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}