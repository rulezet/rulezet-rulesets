rule Trojan_Win32_SusKernelCallBackTable_AM_2{
	meta:
		description = "Trojan:Win32/SusKernelCallBackTable.AM,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4b 65 72 6e 65 6c 43 61 6c 6c 62 61 63 6b 54 61 62 6c 65 00 } 		$a_01_1 = {53 65 6e 64 4d 65 73 73 61 67 65 00 } 		$a_01_2 = {66 6e 43 4f 50 59 44 41 54 41 00 } 		$a_01_3 = {6d 73 69 6e 66 6f 33 32 2e 65 78 65 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}