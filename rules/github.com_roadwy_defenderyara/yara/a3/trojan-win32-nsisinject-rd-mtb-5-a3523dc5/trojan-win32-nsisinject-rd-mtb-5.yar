rule Trojan_Win32_NSISInject_RD_MTB_5{
	meta:
		description = "Trojan:Win32/NSISInject.RD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 69 6e 64 6f 77 73 5c 46 6f 74 6f 65 72 6e 65 73 5c 55 6e 69 6e 73 74 61 6c 6c 5c 49 6e 68 61 6c 61 74 6f 72 65 6e 32 32 34 } 		$a_01_1 = {46 61 72 76 65 62 61 61 6e 64 73 6f 6d 73 6b 69 66 74 65 72 65 6e 2e 74 78 74 } 		$a_01_2 = {41 70 70 6c 69 63 61 74 69 6f 6e 20 44 61 74 61 5c 63 61 6d 65 6c 68 61 69 72 2e 75 64 67 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}