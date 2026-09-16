rule SoftwareBundler_Win32_Pokavampo{
	meta:
		description = "SoftwareBundler:Win32/Pokavampo,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {63 6c 6f 75 64 66 72 6f 6e 74 2e 6e 65 74 2f 57 69 6e 43 68 65 63 6b 53 65 74 75 70 2e 65 78 65 00 } 		$a_01_1 = {57 6d 69 49 6e 73 70 65 63 74 6f 72 2e 64 6c 6c 00 } 		$a_01_2 = {26 70 72 3d 76 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}