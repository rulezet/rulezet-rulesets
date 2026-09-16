rule Trojan_Win32_NSISInject_RK_MTB_4{
	meta:
		description = "Trojan:Win32/NSISInject.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {55 6e 69 6e 73 74 61 6c 6c 5c 52 68 6f 6d 62 6f 76 61 74 65 5c 43 61 63 68 75 63 68 61 73 } 		$a_01_1 = {52 61 66 66 69 61 73 5c 41 63 74 69 6f 6e 66 69 6c 6d 68 65 6c 74 65 5c 45 6c 69 6d 61 72 5c 54 75 72 6e 6b 6d 74 65 61 74 72 65 2e 69 6e 69 } 		$a_01_2 = {53 6f 66 74 77 61 72 65 5c 4d 61 67 61 73 69 6e 5c 4f 73 74 69 6e 64 69 65 6e } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}