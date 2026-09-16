rule BrowserModifier_Win32_Prifou_2{
	meta:
		description = "BrowserModifier:Win32/Prifou,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_00_0 = {45 49 6e 76 61 6c 69 64 4f 70 65 72 61 74 69 6f 6e } 		$a_00_1 = {76 69 72 74 75 61 6c 61 6c 6c 6f 63 } 		$a_00_2 = {56 69 72 74 75 61 6c 46 72 65 65 } 		$a_02_3 = {8b 45 fc 80 b8 ?? 00 00 00 00 74 ec } 		$a_02_4 = {ff ff 84 c0 74 ?? e8 ?? ?? 00 00 68 } 		$a_03_5 = {ff ff 5d c2 10 00 90 09 0a 00 a1 ?? ?? ?? 00 8b 00 e8 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1+(#a_02_3  & 1)*1+(#a_02_4  & 1)*1+(#a_03_5  & 1)*1) >=5
 
}