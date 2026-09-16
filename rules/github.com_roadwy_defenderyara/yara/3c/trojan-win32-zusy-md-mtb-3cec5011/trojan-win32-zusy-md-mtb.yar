rule Trojan_Win32_Zusy_MD_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0e 00 0e 00 05 00 00 "
		
	strings :
		$a_01_0 = {4d 4f 4e 49 42 55 59 56 54 59 2e 44 4c 4c } 		$a_01_1 = {4c 68 62 75 67 76 79 55 66 79 63 74 64 } 		$a_01_2 = {4d 6e 69 62 46 63 74 } 		$a_01_3 = {4f 6e 6a 69 68 47 63 72 74 } 		$a_01_4 = {47 65 74 43 75 72 72 65 6e 74 50 72 6f 63 65 73 73 49 64 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=14
 
}