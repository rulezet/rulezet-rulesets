rule Trojan_Win32_Farfli_MH_MTB{
	meta:
		description = "Trojan:Win32/Farfli.MH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,09 00 09 00 05 00 00 "
		
	strings :
		$a_01_0 = {3a 5c 57 69 6e 64 6f 77 73 5c 44 4e 6f 6d 62 5c 4d 70 65 63 2e 6d 62 74 } 		$a_01_1 = {3a 2f 2f 77 68 74 74 79 2e 6f 73 73 2d 63 6e 2d 68 6f 6e 67 6b 6f 6e 67 2e 61 6c 69 79 75 6e 63 73 2e 63 6f 6d } 		$a_01_2 = {63 6d 64 2e 65 78 65 20 2f 63 20 64 65 6c } 		$a_01_3 = {5c 73 68 65 6c 6c 5c 6f 70 65 6e 5c 63 6f 6d 6d 61 6e 64 } 		$a_01_4 = {43 00 74 00 72 00 6c 00 2b 00 50 00 61 00 67 00 65 00 44 00 6f 00 77 00 6e 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=9
 
}