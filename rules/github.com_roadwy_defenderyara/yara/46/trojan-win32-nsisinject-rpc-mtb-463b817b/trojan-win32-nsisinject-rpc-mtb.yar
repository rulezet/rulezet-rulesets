rule Trojan_Win32_NSISInject_RPC_MTB{
	meta:
		description = "Trojan:Win32/NSISInject.RPC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {4f 70 72 69 64 73 6e 69 6e 67 } 		$a_01_1 = {53 6f 66 74 77 61 72 65 5c 43 6f 6d 6d 75 6e 69 73 74 65 72 69 65 73 5c 4d 61 73 73 65 73 6b 72 69 76 65 6c 73 65 72 73 5c 4c 65 6a 64 65 72 73 5c 49 6e 64 6b 6f 6d 73 74 62 65 73 6b 61 74 74 65 64 65 } 		$a_01_2 = {48 65 74 65 72 6f 67 6f 6e 6f 75 73 6c 79 2e 41 66 6c } 		$a_01_3 = {53 61 6d 74 61 6c 65 70 61 72 74 6e 65 72 73 2e 53 76 75 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}