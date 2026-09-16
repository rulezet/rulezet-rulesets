rule SoftwareBundler_Win32_Trawlmernib{
	meta:
		description = "SoftwareBundler:Win32/Trawlmernib,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {2e 3f 41 56 52 61 6d 62 6c 65 72 50 61 67 65 40 40 } 		$a_01_1 = {52 00 55 00 70 00 64 00 61 00 74 00 65 00 5f 00 25 00 73 00 2e 00 65 00 78 00 65 00 00 00 } 		$a_01_2 = {64 00 6c 00 2e 00 7a 00 76 00 75 00 2e 00 63 00 6f 00 6d 00 2f 00 70 00 69 00 6e 00 73 00 74 00 61 00 6c 00 6c 00 2f 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}