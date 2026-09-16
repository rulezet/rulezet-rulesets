rule Adware_Win32_AdRotator_10{
	meta:
		description = "Adware:Win32/AdRotator,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {44 6c 6c 41 63 74 69 6f 6e } 		$a_00_1 = {44 6c 6c 43 61 6e 55 6e 6c 6f 61 64 4e 6f 77 } 		$a_02_2 = {b8 32 00 00 00 66 a3 ?? ?? ?? ?? b9 79 00 00 00 66 89 0d ?? ?? ?? ?? b8 52 00 00 00 66 a3 ?? ?? ?? ?? ba 44 00 00 00 66 89 15 ?? ?? ?? ?? b9 5c 00 00 00 66 89 0d ?? ?? ?? ?? 33 c9 b8 49 00 00 00 66 a3 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}