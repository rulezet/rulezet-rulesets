rule Trojan_Win32_Guloader_RR_MTB_4{
	meta:
		description = "Trojan:Win32/Guloader.RR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {4c 69 6d 62 65 72 65 72 40 73 69 74 64 6f 77 6e 73 74 72 65 6a 6b 65 73 2e 46 6f 72 31 } 		$a_01_1 = {43 6f 70 61 72 63 65 6e 65 72 20 52 65 73 74 61 75 72 65 72 69 6e 67 73 61 72 62 65 6a 64 65 73 20 53 61 6d 6d 65 6e 68 66 74 6e 69 6e 67 73 20 31 } 		$a_01_2 = {67 6f 6c 6c 75 62 31 39 30 37 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}