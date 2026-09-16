rule BrowserModifier_Win32_Monkostey_3{
	meta:
		description = "BrowserModifier:Win32/Monkostey,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {6a 73 58 6a 69 66 89 ?? ?? 58 6a 4d 66 89 ?? ?? 58 6a 61 66 89 ?? ?? 58 66 89 ?? ?? 6a 53 33 c0 66 89 ?? ?? 58 6a 66 } 		$a_03_1 = {0f b7 08 66 83 f9 2d 74 ?? 66 83 f9 2f 0f ?? ?? 00 00 00 6a 73 59 6a 61 66 89 4d ?? 66 89 4d ?? 59 6a 6d 66 89 4d ?? 59 66 89 4d ?? 33 c9 6a 73 } 		$a_03_2 = {c7 46 10 04 00 00 00 89 5e 14 89 5e 18 89 5e 1c 89 5e 20 89 5d fc 68 08 02 00 00 8d 46 3c 53 50 c7 ?? ?? ?? ?? 00 88 5e 28 89 5e 2c c7 46 34 e8 03 00 00 89 5e 38 e8 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}