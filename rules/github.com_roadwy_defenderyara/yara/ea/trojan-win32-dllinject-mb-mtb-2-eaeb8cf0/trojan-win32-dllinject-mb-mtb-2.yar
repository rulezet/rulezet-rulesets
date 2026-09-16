rule Trojan_Win32_DllInject_MB_MTB_2{
	meta:
		description = "Trojan:Win32/DllInject.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 06 00 00 "
		
	strings :
		$a_01_0 = {71 77 65 72 2e 64 6c 6c 00 4f 6e 65 46 00 54 77 6f 46 00 54 68 72 46 } 		$a_01_1 = {4f 6e 65 46 } 		$a_01_2 = {54 77 6f 46 } 		$a_01_3 = {54 68 72 46 } 		$a_01_4 = {71 77 65 72 2e 64 6c 6c } 		$a_01_5 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*3+(#a_01_5  & 1)*1) >=23
 
}