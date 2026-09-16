rule Trojan_Win32_NSISInject_RPX_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RPX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {50 61 72 62 61 74 65 2e 52 65 61 } 		$a_01_1 = {46 69 65 72 63 65 6e 69 6e 67 5c 56 69 72 74 75 73 } 		$a_01_2 = {41 6e 67 72 65 62 73 6d 65 74 6f 64 65 72 31 36 35 2e 4c 6b 6b } 		$a_01_3 = {55 6e 69 6e 73 74 61 6c 6c 5c 4c 69 74 69 6f 70 61 } 		$a_01_4 = {53 6f 66 74 77 61 72 65 5c 52 6f 6f 79 65 62 6f 6b } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}