rule Trojan_Win32_NSISInject_RE_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 79 6e 64 65 72 6e 65 31 35 39 5c 41 74 72 69 63 68 69 63 2e 69 6e 69 } 		$a_01_1 = {52 68 79 6d 65 73 31 31 32 2e 69 6e 69 } 		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 43 72 65 6f 73 6f 6c 73 } 		$a_01_3 = {53 6f 66 74 77 61 72 65 5c 4b 6c 75 73 69 6c 65 6e 73 } 		$a_01_4 = {42 72 6e 64 69 6e 67 65 72 73 2e 64 6c 6c } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}