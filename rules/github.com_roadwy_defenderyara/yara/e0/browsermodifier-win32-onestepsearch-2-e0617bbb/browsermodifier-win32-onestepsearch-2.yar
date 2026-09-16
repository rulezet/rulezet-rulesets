rule BrowserModifier_Win32_OneStepSearch_2{
	meta:
		description = "BrowserModifier:Win32/OneStepSearch,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {40 00 ff 75 0c 50 e8 4e ff ff ff 0b c0 75 07 bb 01 00 00 00 eb 34 83 c0 08 89 45 f8 2b 45 fc 83 7d 10 00 74 03 83 e8 08 3d 00 08 00 00 } 		$a_03_1 = {25 ff ff 00 00 bb 69 90 90 00 00 f7 e3 8b 1d ?? ?? 40 00 c1 eb 10 03 c3 a3 ?? ?? 40 00 a1 ?? ?? 40 00 25 ff ff 00 00 bb 69 90 90 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}