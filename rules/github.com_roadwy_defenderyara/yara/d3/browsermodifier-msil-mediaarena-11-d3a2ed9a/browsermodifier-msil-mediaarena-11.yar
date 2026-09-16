rule BrowserModifier_MSIL_MediaArena_11{
	meta:
		description = "BrowserModifier:MSIL/MediaArena,SIGNATURE_TYPE_PEHSTR,08 00 08 00 06 00 00 "
		
	strings :
		$a_01_0 = {4f 66 66 65 72 53 63 72 65 65 6e } 		$a_01_1 = {6f 66 66 65 72 57 69 6e 64 6f 77 } 		$a_01_2 = {49 5f 44 53 5f 54 5f 59 5f 50 5f 4f 50 45 4e 45 44 } 		$a_01_3 = {49 5f 44 53 5f 46 46 5f 53 45 54 5f 54 49 4e 47 53 5f 53 45 45 52 52 43 48 5f 45 4e 47 } 		$a_01_4 = {42 72 6f 77 73 65 72 4c 6f 61 64 65 64 57 69 74 68 55 72 6c } 		$a_01_5 = {4d 79 50 64 66 4d 61 6e 61 67 65 72 2e 70 64 62 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*2+(#a_01_4  & 1)*1+(#a_01_5  & 1)*2) >=8
 
}