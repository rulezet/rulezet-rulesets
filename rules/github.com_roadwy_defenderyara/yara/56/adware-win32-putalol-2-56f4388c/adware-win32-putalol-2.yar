rule Adware_Win32_Putalol_2{
	meta:
		description = "Adware:Win32/Putalol,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 04 00 00 "
		
	strings :
		$a_03_0 = {49 83 fb 10 48 0f 43 c3 42 0f b6 14 10 4c 8d 45 ?? 4c 0f 43 c3 ?? 0f b6 ce 41 f6 d1 0f b6 ca f6 d1 ?? 22 ce 41 0f b6 c1 22 c2 0a c8 43 88 0c 10 } 		$a_03_1 = {49 83 f9 10 49 0f 43 c3 41 0f b6 14 02 4c 8d 45 ?? 4d 0f 43 c3 0f b6 ca f6 d1 41 22 ce 41 0f b6 c6 f6 d0 22 c2 0a c8 43 88 0c 10 } 		$a_03_2 = {44 8d 40 39 48 8d 15 ?? ?? ?? ?? 48 8d 4c 24 ?? e8 ?? ?? ?? ?? 48 8b d8 90 09 03 00 41 b1 } 		$a_03_3 = {48 8b d8 41 b1 ?? 41 b8 ?? 00 00 00 48 8d 15 ?? ?? ?? ?? 48 8d 4d ?? e8 90 09 19 00 41 b1 ?? 41 b8 ?? 00 00 00 48 8d 15 ?? ?? ?? ?? 48 8d 4d ?? e8 } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_03_2  & 1)*1+(#a_03_3  & 1)*1) >=3
 
}