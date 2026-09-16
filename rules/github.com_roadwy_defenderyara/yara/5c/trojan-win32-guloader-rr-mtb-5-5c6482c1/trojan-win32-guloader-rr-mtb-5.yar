rule Trojan_Win32_Guloader_RR_MTB_5{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {46 6f 72 6c 79 64 65 6e 64 65 72 6e 65 40 48 65 6d 69 73 70 68 65 72 69 63 61 6c 33 36 2e 4e 6f 31 } 		$a_01_1 = {44 65 74 61 6c 6a 65 70 72 6f 6a 65 6b 74 73 31 } 		$a_01_2 = {25 42 72 61 69 6e 73 74 6f 72 6d 69 6e 67 65 72 6e 65 20 46 72 69 74 74 65 74 20 4d 6f 6e 61 72 63 68 69 73 6d 20 31 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}