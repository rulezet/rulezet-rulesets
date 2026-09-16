rule Trojan_Win32_NSISInject_RPG_MTB_2{
	meta:
		description = "Trojan:Win32/NSISInject.RPG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {46 65 72 72 69 6d 61 67 6e 65 74 69 63 61 6c 6c 79 } 		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 44 69 73 6f 72 64 65 72 65 72 5c 4d 65 64 6c 65 6d 73 6c 69 73 74 65 72 5c 50 65 61 73 63 6f 64 } 		$a_01_2 = {42 61 6e 6a 6f 73 2e 42 65 76 } 		$a_01_3 = {46 6f 6c 64 6e 69 6e 67 73 73 74 6e 69 6e 67 65 72 6e 65 } 		$a_01_4 = {6f 75 74 73 70 65 6e 74 2e 52 6f 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}