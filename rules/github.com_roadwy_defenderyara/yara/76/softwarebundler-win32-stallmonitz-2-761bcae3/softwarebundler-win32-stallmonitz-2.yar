rule SoftwareBundler_Win32_Stallmonitz_2{
	meta:
		description = "SoftwareBundler:Win32/Stallmonitz,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {7b 74 6d 70 7d 5c 49 6e 73 74 61 6c 6c 2e 65 78 65 } 		$a_01_1 = {68 74 74 70 3a 2f 2f 77 77 77 2e 6e 74 64 6c 7a 6f 6e 65 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}