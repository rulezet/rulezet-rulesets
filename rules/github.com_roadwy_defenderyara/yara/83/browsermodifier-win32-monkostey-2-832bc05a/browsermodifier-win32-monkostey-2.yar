rule BrowserModifier_Win32_Monkostey_2{
	meta:
		description = "BrowserModifier:Win32/Monkostey,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {8b 45 0c 53 33 db 83 7d 08 02 c6 45 ?? 65 c6 45 ?? 6e c6 45 ?? 4d c6 45 ?? 75 c6 45 ?? 52 c6 45 ?? 61 } 		$a_03_1 = {8d 45 d4 50 6a 02 53 89 75 d4 c7 45 ?? 03 00 00 00 89 75 ?? 89 75 ?? 89 75 ?? ff 15 ?? ?? ?? ?? 53 8b f0 ff d7 eb } 		$a_03_2 = {ff d7 53 6a 26 bd ?? ?? ?? ?? 55 53 ff d6 68 ?? ?? ?? ?? 55 ff d7 53 6a 23 bd ?? ?? ?? ?? 55 53 ff d6 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}