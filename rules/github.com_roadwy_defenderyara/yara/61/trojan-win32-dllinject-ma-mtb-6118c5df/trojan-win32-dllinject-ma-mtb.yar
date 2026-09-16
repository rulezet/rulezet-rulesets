rule Trojan_Win32_DllInject_MA_MTB{
	meta:
		description = "Trojan:Win32/DllInject.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {4f 6e 65 50 72 6f } 		$a_01_1 = {54 77 6f 50 72 6f } 		$a_01_2 = {54 68 72 50 72 6f } 		$a_01_3 = {65 73 74 61 74 65 2e 64 6c 6c } 		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1) >=13
 
}