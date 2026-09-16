rule Trojan_Win32_Guloader_SLA_MTB{
	meta:
		description = "Trojan:Win32/Guloader.SLA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_01_0 = {6b 65 72 6e 65 6d 65 64 6c 65 6d 6d 65 72 6e 65 2e 6b 61 66 } 		$a_01_1 = {5c 6d 6f 64 65 6d 6c 69 6e 69 65 72 6e 65 73 5c 65 6e 74 72 79 6d 61 6e 2e 74 78 74 22 } 		$a_01_2 = {35 5c 68 65 6d 69 68 79 70 6f 65 73 74 68 65 73 69 61 2e 69 6e 69 } 		$a_01_3 = {66 6c 6f 61 74 61 74 69 6f 6e 5c 6b 6f 6c 6c 65 6b 74 69 76 69 73 65 72 69 6e 67 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2+(#a_01_2  & 1)*2+(#a_01_3  & 1)*2) >=8
 
}