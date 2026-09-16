rule Trojan_Win32_Gepys_B{
	meta:
		description = "Trojan:Win32/Gepys.B,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {3d d5 c6 dd c3 75 04 b0 01 eb 32 3d 10 5f e3 b4 74 f5 3d d1 ed 7a 26 } 		$a_03_1 = {c7 45 fc 20 37 ef c6 c7 45 f4 20 00 00 00 ff 75 10 ff 75 fc 57 6a 0b 59 e8 ?? ?? ?? ?? ff 75 10 81 45 fc 47 86 c8 61 } 		$a_01_2 = {0f b7 46 24 8b 4e 28 d1 e8 85 c9 74 20 85 c0 74 1c 8d 54 41 fe 66 83 3a 5c 74 06 83 ea 02 48 75 f4 8d 04 41 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}