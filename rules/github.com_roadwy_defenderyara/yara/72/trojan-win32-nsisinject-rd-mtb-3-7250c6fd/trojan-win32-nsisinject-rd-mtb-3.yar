rule Trojan_Win32_NSISInject_RD_MTB_3{
	meta:
		description = "Trojan:Win32/NSISInject.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {64 79 6b 6b 65 72 65 5c 55 6e 69 6e 73 74 61 6c 6c 5c 6a 6f 73 69 61 73 73 } 		$a_01_1 = {6d 61 6e 69 66 65 73 74 61 74 69 6f 6e 65 72 5c 62 65 74 76 69 76 6c 65 2e 69 6e 69 } 		$a_01_2 = {5c 4b 75 6c 74 75 72 66 6f 72 73 6b 65 6c 6c 65 5c 70 72 6f 67 72 61 6d 6d 72 2e 69 6e 69 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}