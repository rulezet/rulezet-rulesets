rule Trojan_Win32_NSISInject_RPI_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_81_0 = {57 61 6c 6c 6f 77 65 72 73 5c 46 6f 72 61 6e 73 74 69 6c 6c 65 74 31 35 35 5c 52 65 74 74 65 70 72 6f 67 72 61 6d 6d 65 72 6e 65 73 31 34 5c 50 61 72 64 68 61 6e } 		$a_81_1 = {53 74 6f 77 65 79 2e 50 61 61 } 		$a_81_2 = {46 6f 72 74 61 6c 65 6e 64 65 73 } 		$a_81_3 = {53 61 70 69 64 69 74 79 2e 63 68 69 } 		$a_81_4 = {53 75 62 61 6e 67 6c 65 64 2e 69 6e 69 } 	condition:
		((#a_81_0  & 1)*1+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1+(#a_81_4  & 1)*1) >=5
 
}