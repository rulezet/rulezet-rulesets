rule BrowserModifier_Win32_MediaArena{
	meta:
		description = "BrowserModifier:Win32/MediaArena,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {67 65 74 5f 54 68 61 6e 6b 79 6f 75 50 61 67 65 55 72 6c } 		$a_80_1 = {67 65 74 5f 55 6e 69 6e 73 74 61 6c 6c 53 65 61 72 63 68 55 72 6c } 		$a_80_2 = {67 65 74 5f 53 74 61 74 73 55 72 6c } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1) >=3
 
}