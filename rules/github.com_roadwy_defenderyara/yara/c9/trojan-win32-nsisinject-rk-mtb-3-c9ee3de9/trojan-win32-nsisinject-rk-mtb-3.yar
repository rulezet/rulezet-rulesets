rule Trojan_Win32_NSISInject_RK_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {6f 70 67 72 61 76 65 64 65 73 2e 64 6c 6c } 		$a_01_1 = {41 6e 6c 67 73 6f 70 67 61 76 65 72 2e 69 6e 69 } 		$a_01_2 = {53 79 64 6c 69 67 2e 69 6e 69 } 		$a_01_3 = {43 61 76 61 6c 69 65 72 65 64 5c 50 6f 72 74 75 6c 61 6b 6b 65 72 2e 69 6e 69 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}