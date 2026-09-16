rule SoftwareBundler_Win32_Stallmonitz_4{
	meta:
		description = "SoftwareBundler:Win32/Stallmonitz,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {72 75 6e 20 64 61 74 61 5c 6d 74 72 2e 65 78 65 } 		$a_01_1 = {72 75 6e 77 61 69 74 20 64 61 74 61 5c 62 67 62 2e 65 78 65 20 2f 43 42 55 52 4c 3d 68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 6f 63 74 64 6c 66 61 73 74 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}