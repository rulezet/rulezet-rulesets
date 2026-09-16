rule BrowserModifier_MSIL_MediaArena{
	meta:
		description = "BrowserModifier:MSIL/MediaArena,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {50 44 46 61 6c 63 6f 6e } 		$a_80_1 = {4f 66 66 65 72 53 63 72 65 65 6e } 		$a_80_2 = {6f 66 66 65 72 57 69 6e 64 6f 77 } 		$a_80_3 = {63 6f 6d 70 6f 6e 65 6e 74 2f 6f 66 66 65 72 73 63 72 65 65 6e 2e 78 61 6d 6c } 		$a_80_4 = {50 6f 70 75 70 53 6c 65 65 70 35 } 		$a_80_5 = {42 4c 42 65 61 63 6f 6e } 	condition:
		((#a_80_0  & 1)*2+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}