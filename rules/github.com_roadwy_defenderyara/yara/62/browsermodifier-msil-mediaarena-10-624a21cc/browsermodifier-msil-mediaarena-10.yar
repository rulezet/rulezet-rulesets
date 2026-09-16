rule BrowserModifier_MSIL_MediaArena_10{
	meta:
		description = "BrowserModifier:MSIL/MediaArena,SIGNATURE_TYPE_PEHSTR,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4f 66 66 65 72 53 63 72 65 65 6e } 		$a_01_1 = {5f 6f 66 66 65 72 57 69 6e 64 6f 77 } 		$a_01_2 = {4d 79 50 64 66 4d 61 6e 61 67 65 72 2e 67 2e 72 65 73 6f 75 72 63 65 73 } 		$a_01_3 = {4f 66 66 65 72 44 65 73 63 } 		$a_01_4 = {4d 79 50 64 66 4d 61 6e 61 67 65 72 2e 65 78 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}