rule PWS_Win32_Frethog_MK_2{
	meta:
		description = "PWS:Win32/Frethog.MK,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 05 00 00 "
		
	strings :
		$a_03_0 = {68 4b e1 22 00 ff 75 08 ff 15 ?? ?? ?? ?? 85 c0 74 0f ff 15 } 		$a_03_1 = {66 70 69 64 c7 45 ?? 73 64 6f 73 ff 15 } 		$a_01_2 = {66 81 7d fc e8 e8 74 0c 46 83 fe 05 7c bf } 		$a_03_3 = {74 46 56 be ?? ?? ?? ?? ff 36 8d 85 fc fe ff ff 50 ff 15 ?? ?? ?? ?? 59 85 c0 59 74 0d } 		$a_03_4 = {73 22 2b 08 8d 45 e0 50 ff 75 f0 03 4d e4 ff 75 08 89 4d e0 e8 ?? ?? ?? ?? 83 c4 0c 83 c6 04 ff 45 f0 eb cc } 	condition:
		((#a_03_0  & 1)*2+(#a_03_1  & 1)*2+(#a_01_2  & 1)*1+(#a_03_3  & 1)*1+(#a_03_4  & 1)*1) >=3
 
}