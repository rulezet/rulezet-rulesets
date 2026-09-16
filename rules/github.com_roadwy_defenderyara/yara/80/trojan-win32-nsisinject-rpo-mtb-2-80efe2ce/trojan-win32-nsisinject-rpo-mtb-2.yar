rule Trojan_Win32_NSISInject_RPO_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {53 70 6f 6e 64 79 6c 75 73 2e 52 65 69 } 		$a_01_1 = {48 6f 6c 6f 63 65 6e 74 72 69 64 2e 53 74 75 } 		$a_01_2 = {52 65 67 65 6c 66 61 73 74 73 74 74 65 6c 73 65 72 6e 65 73 2e 64 6c 6c } 		$a_01_3 = {48 79 70 6e 6f 74 68 65 72 61 70 69 73 74 35 30 2e 4e 6f 6e } 		$a_01_4 = {4d 69 63 72 6f 67 61 6d 79 5c 42 65 6b 6c 64 74 2e 42 75 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}