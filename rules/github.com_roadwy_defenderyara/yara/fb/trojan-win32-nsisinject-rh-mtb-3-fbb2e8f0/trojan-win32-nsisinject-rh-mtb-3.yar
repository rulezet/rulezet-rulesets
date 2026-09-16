rule Trojan_Win32_NSISInject_RH_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {49 6e 6b 6f 72 70 6f 72 65 72 65 64 65 73 2e 6c 6e 6b } 		$a_01_1 = {46 65 6c 69 6e 65 73 2e 64 6c 6c } 		$a_01_2 = {55 6e 69 6e 73 74 61 6c 6c 5c 50 72 65 68 65 6e 73 69 76 65 5c 49 6e 64 65 73 70 72 72 69 6e 67 65 72 6e 65 73 } 		$a_01_3 = {56 61 67 65 72 62 6a 65 2e 69 6e 69 } 		$a_01_4 = {46 75 6e 6b 74 69 6f 6e 72 6c 6f 76 65 6e 65 6e 2e 42 6c 6f } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}