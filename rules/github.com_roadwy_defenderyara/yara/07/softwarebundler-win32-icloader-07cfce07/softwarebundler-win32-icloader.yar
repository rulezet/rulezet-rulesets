rule SoftwareBundler_Win32_ICLoader{
	meta:
		description = "SoftwareBundler:Win32/ICLoader,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {66 81 39 4d 5a 0f 85 ?? ?? 00 00 8b 41 3c 68 00 01 00 00 03 c1 50 a3 ?? ?? ?? ?? ff d6 85 c0 0f 85 ?? ?? 00 00 a1 ?? ?? ?? ?? 66 81 38 50 45 } 		$a_01_1 = {75 0b 33 1a ff d3 cc } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}