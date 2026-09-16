rule Adware_Win32_AdRotator_8{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {62 72 6f 77 73 65 72 20 65 6e 68 61 6e 63 65 72 } 		$a_03_1 = {8a 04 3e 3c 28 7c ?? 3c 7e 7f [0-04] 0f be d0 a1 ?? ?? ?? ?? 8a 54 02 ?? 88 11 eb 02 } 		$a_03_2 = {8b f0 ff d5 2b f0 83 ee ?? eb 0e 90 09 10 00 74 19 68 ?? ?? ?? ?? 57 ff d5 68 ?? ?? ?? ?? 57 } 	condition:
		((#a_00_0  & 1)*1+(#a_03_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}