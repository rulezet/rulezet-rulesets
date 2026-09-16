rule SoftwareBundler_Win32_Prepscram{
	meta:
		description = "SoftwareBundler:Win32/Prepscram,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 02 00 00 00 80 34 30 ?? 83 c0 03 3d ?? ?? ?? ?? 72 f2 8b 47 08 68 00 b0 00 00 ff 70 04 ff d6 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}