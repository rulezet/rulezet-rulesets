rule Trojan_Win32_Guloader_RR_MTB_3{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {50 6f 64 7a 6f 6c 69 63 20 53 75 6e 62 65 6c 74 73 20 73 74 69 63 6b 62 6f 61 74 20 31 } 		$a_01_1 = {53 6b 6e 64 73 65 6c 73 67 65 72 6e 69 6e 67 73 40 6a 75 73 73 69 76 65 73 2e 62 61 31 } 		$a_01_2 = {48 65 6d 69 64 61 63 74 79 6c 6f 75 73 31 25 30 23 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}