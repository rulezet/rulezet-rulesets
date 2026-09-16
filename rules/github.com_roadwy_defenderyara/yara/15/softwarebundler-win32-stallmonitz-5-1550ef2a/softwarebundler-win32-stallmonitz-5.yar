rule SoftwareBundler_Win32_Stallmonitz_5{
	meta:
		description = "SoftwareBundler:Win32/Stallmonitz,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_01_0 = {7b 61 70 70 7d 5c 43 42 53 74 75 62 2e 65 78 65 } 		$a_01_1 = {2f 43 42 55 52 4c 3d 68 74 74 70 3a 2f 2f 77 77 77 2e 6d 69 63 6b 79 66 61 73 74 64 6c 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } 		$a_01_2 = {2f 43 42 55 52 4c 3d 68 74 74 70 3a 2f 2f 77 77 77 2e 63 6f 6a 75 6c 79 66 61 73 74 64 6c 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=11
 
}