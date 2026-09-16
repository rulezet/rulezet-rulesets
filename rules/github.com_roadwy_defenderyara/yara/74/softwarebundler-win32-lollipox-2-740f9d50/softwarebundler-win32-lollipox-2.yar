rule SoftwareBundler_Win32_Lollipox_2{
	meta:
		description = "SoftwareBundler:Win32/Lollipox,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 6c 6c 69 70 6f 70 2d 6e 65 74 77 6f 72 6b 2e 63 6f 6d 2f 65 75 6c 61 2e 70 68 70 } 		$a_01_1 = {4d 65 63 61 4e 65 74 } 		$a_03_2 = {4c 6f 6c 6c 69 70 6f 70 [0-10] 69 73 20 61 20 66 72 65 65 20 61 70 70 6c 69 63 61 74 69 6f 6e } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=5
 
}