rule Trojan_Win32_Guloader_RR_MTB_2{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {75 6e 64 65 72 66 6f 72 73 74 61 61 65 64 65 40 49 6e 6d 65 73 68 69 6e 67 2e 54 72 31 } 		$a_01_1 = {45 66 74 65 72 6d 6c 65 74 31 23 30 21 } 		$a_01_2 = {46 61 79 65 74 74 69 73 6d 20 4e 64 65 74 20 4c 65 76 61 6e 74 69 6e 65 72 20 31 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}