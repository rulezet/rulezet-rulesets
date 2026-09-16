rule Trojan_Win32_NSISInject_RPX_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {76 61 72 65 69 6e 64 6b 62 65 6e 65 73 2e 54 69 6c } 		$a_01_1 = {73 69 64 65 6f 72 64 6e 65 74 2e 73 6c 69 } 		$a_01_2 = {70 61 6c 6c 69 61 74 65 73 5c 63 6f 6f 69 6e 67 } 		$a_01_3 = {42 65 74 69 6e 67 65 6c 73 65 73 64 65 6c 65 6e 73 } 		$a_01_4 = {41 75 74 6f 6b 6c 61 76 65 72 69 6e 67 65 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}