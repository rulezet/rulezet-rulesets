rule BrowserModifier_Win32_MediaArena_2{
	meta:
		description = "BrowserModifier:Win32/MediaArena,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_80_0 = {4f 66 66 65 72 53 63 72 65 65 6e } 		$a_80_1 = {49 44 53 5f 44 45 46 41 55 4c 54 5f 53 45 41 52 43 48 5f 50 52 4f 56 49 44 45 52 5f 44 41 54 41 } 		$a_80_2 = {49 44 53 5f 53 45 41 52 43 48 5f 42 4f 58 5f 4f 50 54 49 4f 4e } 		$a_80_3 = {6f 66 66 65 72 57 69 6e 64 6f 77 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=4
 
}