rule SoftwareBundler_Win32_Ogimant{
	meta:
		description = "SoftwareBundler:Win32/Ogimant,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2f 2f 66 6f 72 63 65 73 2e 73 75 6e 73 68 69 6e 65 62 6c 6f 67 2e 72 75 2f 67 65 74 5f 6a 73 6f 6e 3f 73 74 62 3d 34 26 64 69 64 3d 90 04 09 0a 30 31 32 33 34 35 36 37 38 39 26 65 78 74 5f 70 61 72 74 6e 65 72 5f 69 64 3d 26 66 69 6c 65 5f 69 64 3d 90 04 09 0a 30 31 32 33 34 35 36 37 38 39 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}