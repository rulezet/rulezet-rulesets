rule SoftwareBundler_Win32_Stallmonitz{
	meta:
		description = "SoftwareBundler:Win32/Stallmonitz,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {77 77 77 2e 63 6f 6f 63 74 64 6c 66 61 73 74 2e 63 6f 6d 2f 64 6f 77 6e 6c 6f 61 64 2e 70 68 70 3f } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}