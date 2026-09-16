rule Trojan_Win32_NSISInject_RC_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 69 6b 72 6f 73 6b 6f 70 65 72 65 2e 6c 6e 6b } 		$a_01_1 = {53 6b 75 6d 73 6c 75 6b 6b 65 72 65 6e 2e 69 6e 69 } 		$a_01_2 = {50 65 72 73 69 73 6b 2e 6c 6e 6b } 		$a_01_3 = {72 61 66 66 69 6e 61 64 65 72 69 70 72 6f 64 75 6b 74 73 2e 69 6e 69 } 		$a_01_4 = {43 6f 6c 75 6d 6e 69 7a 69 6e 67 2e 64 6c 6c } 		$a_01_5 = {73 6f 6c 69 6e 67 6b 6c 61 73 73 65 72 6e 65 73 2e 69 6e 69 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=5
 
}