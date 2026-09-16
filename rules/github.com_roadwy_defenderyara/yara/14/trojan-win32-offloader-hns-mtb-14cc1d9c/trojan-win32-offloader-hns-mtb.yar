rule Trojan_Win32_OffLoader_HNS_MTB{
	meta:
		description = "Trojan:Win32/OffLoader.HNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_80_0 = {49 6e 6e 6f 44 6f 77 6e 6c 6f 61 64 50 6c 75 67 69 6e 2f 31 2e 35 } 		$a_80_1 = {2e 70 68 70 3f 73 70 6f 74 3d 31 26 61 3d } 		$a_80_2 = {2d 2d 73 69 6c 65 6e 74 20 2d 2d 61 6c 6c 75 73 65 72 73 3d 30 } 		$a_80_3 = {2e 70 68 70 3f 66 7a 3d 26 64 3d 6e 73 69 73 26 6d 73 67 3d 26 72 3d 6f 66 66 65 72 5f 65 78 65 63 75 74 69 6f 6e 26 72 6b 3d 79 65 73 26 6f 3d } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*5) >=8
 
}