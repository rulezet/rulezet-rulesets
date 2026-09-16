rule SoftwareBundler_Win32_Stallmonitz_6{
	meta:
		description = "SoftwareBundler:Win32/Stallmonitz,SIGNATURE_TYPE_PEHSTR_EXT,15 00 15 00 05 00 00 "
		
	strings :
		$a_01_0 = {7b 74 6d 70 7d 5c 73 74 75 62 } 		$a_01_1 = {25 73 25 64 5f 69 6e 73 74 61 6c 6c 2e 65 78 65 } 		$a_01_2 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 6f 63 74 31 33 68 65 6e 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } 		$a_01_3 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 73 65 70 74 31 33 6a 65 74 74 79 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } 		$a_01_4 = {68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 73 65 70 74 31 34 77 61 74 65 72 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=21
 
}