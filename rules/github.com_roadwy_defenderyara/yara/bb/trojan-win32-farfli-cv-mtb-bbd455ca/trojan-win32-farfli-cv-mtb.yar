rule Trojan_Win32_Farfli_CV_MTB{
	meta:
		description = "Trojan:Win32/Farfli.CV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {43 3a 57 69 6e 64 6f 77 73 38 38 2e 65 78 65 } 		$a_01_1 = {32 30 33 2e 31 36 30 2e 35 34 2e 32 35 30 2f 39 } 		$a_01_2 = {40 66 75 63 6b } 		$a_01_3 = {55 52 4c 44 6f 77 6e 6c 6f 61 64 54 6f 46 69 6c 65 41 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}