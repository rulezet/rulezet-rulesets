rule Trojan_Win32_SuspVolumeShadowCopy_ZPB_3{
	meta:
		description = "Trojan:Win32/SuspVolumeShadowCopy.ZPB,SIGNATURE_TYPE_CMDHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {6d 00 6b 00 6c 00 69 00 6e 00 6b 00 } 		$a_00_1 = {20 00 2f 00 44 00 20 00 } 		$a_00_2 = {5c 00 47 00 4c 00 4f 00 42 00 41 00 4c 00 52 00 4f 00 4f 00 54 00 5c 00 44 00 65 00 76 00 69 00 63 00 65 00 5c 00 48 00 61 00 72 00 64 00 64 00 69 00 73 00 6b 00 56 00 6f 00 6c 00 75 00 6d 00 65 00 53 00 68 00 61 00 64 00 6f 00 77 00 43 00 6f 00 70 00 79 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_00_2  & 1)*1) >=3
 
}