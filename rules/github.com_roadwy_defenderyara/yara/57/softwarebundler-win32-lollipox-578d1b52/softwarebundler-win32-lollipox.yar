rule SoftwareBundler_Win32_Lollipox{
	meta:
		description = "SoftwareBundler:Win32/Lollipox,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {6c 6f 6c 6c 69 70 6f 70 2d 6e 65 74 77 6f 72 6b 2e 63 6f 6d 2f 65 75 6c 61 2e 70 68 70 } 		$a_01_1 = {4d 65 63 61 4e 65 74 } 		$a_03_2 = {4d 65 63 61 4e 65 74 [0-02] 5f 4f 66 65 72 74 61 4c 6f 6c 6c 69 50 6f 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_03_2  & 1)*2) >=4
 
}