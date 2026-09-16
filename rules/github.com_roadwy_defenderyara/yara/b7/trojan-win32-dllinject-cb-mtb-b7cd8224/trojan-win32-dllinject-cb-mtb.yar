rule Trojan_Win32_DllInject_CB_MTB{
	meta:
		description = "Trojan:Win32/DllInject.CB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 05 00 00 "
		
	strings :
		$a_01_0 = {4f 6e 65 31 4e 65 6f } 		$a_01_1 = {54 77 6f 32 4e 65 6f } 		$a_01_2 = {54 68 72 33 4e 65 6f } 		$a_01_3 = {72 74 68 72 79 6a 74 2e 64 6c 6c } 		$a_01_4 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3+(#a_01_2  & 1)*3+(#a_01_3  & 1)*3+(#a_01_4  & 1)*1) >=13
 
}