rule SoftwareBundler_Win32_Stallmonitz_3{
	meta:
		description = "SoftwareBundler:Win32/Stallmonitz,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {5c 43 42 53 74 75 62 2d 54 72 61 63 74 69 6f 6e 31 2e 65 78 65 } 		$a_01_1 = {2f 43 42 55 52 4c 3d 68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 61 70 72 31 33 73 6f 75 74 68 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}