rule Trojan_Win32_DllInject_MB_MTB{
	meta:
		description = "Trojan:Win32/DllInject.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,07 00 07 00 04 00 00 "
		
	strings :
		$a_01_0 = {54 66 74 76 67 45 64 72 74 63 66 } 		$a_01_1 = {49 6e 66 66 62 54 76 66 63 72 66 67 } 		$a_01_2 = {50 6b 6d 6a 6e 4c 6d 69 6e 75 } 		$a_01_3 = {57 61 69 74 46 6f 72 53 69 6e 67 6c 65 4f 62 6a 65 63 74 45 78 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*1) >=7
 
}