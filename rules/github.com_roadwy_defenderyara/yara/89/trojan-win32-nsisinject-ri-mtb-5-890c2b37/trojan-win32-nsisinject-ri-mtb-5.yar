rule Trojan_Win32_NSISInject_RI_MTB_5{
	meta:
		description = "Trojan:Win32/NSISInject.RI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {41 66 74 65 72 73 75 70 70 65 72 2e 69 6e 69 } 		$a_01_1 = {4d 69 64 74 73 61 6d 6c 69 6e 67 2e 46 6f 72 } 		$a_01_2 = {53 75 73 70 65 6e 64 79 6a 72 2e 69 6e 69 } 		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 49 72 72 65 76 6f 63 61 62 6c 79 } 		$a_01_4 = {75 6e 63 69 76 69 6c 6e 65 73 73 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}