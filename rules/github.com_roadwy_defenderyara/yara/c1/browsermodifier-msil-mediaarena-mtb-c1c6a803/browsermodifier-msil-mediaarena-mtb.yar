rule BrowserModifier_MSIL_MediaArena_MTB{
	meta:
		description = "BrowserModifier:MSIL/MediaArena!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 06 00 00 "
		
	strings :
		$a_80_0 = {67 65 74 5f 53 68 6f 77 } 		$a_80_1 = {4f 70 74 69 6f 6e 61 6c 4f 66 66 65 72 } 		$a_80_2 = {49 6e 73 74 61 6c 6c 46 72 65 65 50 44 46 } 		$a_80_3 = {67 65 74 5f 42 72 6f 77 73 65 72 54 79 70 65 } 		$a_80_4 = {44 65 66 61 75 6c 74 53 65 61 72 63 68 45 6e 67 69 6e 65 } 		$a_80_5 = {46 72 65 65 50 44 46 50 6c 75 73 49 6e 73 74 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*1) >=6
 
}