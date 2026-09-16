rule BrowserModifier_MSIL_MediaArena_2{
	meta:
		description = "BrowserModifier:MSIL/MediaArena,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 07 00 00 "
		
	strings :
		$a_80_0 = {43 6f 6e 76 65 72 74 4d 61 74 65 } 		$a_80_1 = {42 72 69 65 66 6d 65 2e 6d 70 34 } 		$a_80_2 = {63 5f 68 5f 72 5f 6f 5f 6d 5f 65 5f 2e 5f 65 5f 78 5f 65 } 		$a_80_3 = {43 6f 6e 76 65 72 74 4d 61 74 65 2e 70 64 62 } 		$a_80_4 = {63 6c 69 6d 61 74 63 6f 6e 2e 63 6f 6d } 		$a_80_5 = {55 6e 69 6e 73 74 2e 65 78 65 } 		$a_80_6 = {55 6e 69 6e 73 74 61 6c 6c 2e 65 78 65 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1+(#a_80_4  & 1)*1+(#a_80_5  & 1)*-100+(#a_80_6  & 1)*-100) >=5
 
}