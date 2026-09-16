rule Trojan_Win32_Zusy_MB_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_01_0 = {eb 38 d8 c2 d8 ea d8 ca d8 d1 d8 d0 d8 d4 89 10 d8 d1 d8 c0 88 10 d8 c5 d8 e1 d8 ec d8 c8 d8 db 8a 0c d8 d4 d8 df d8 cd d8 e1 d8 e2 d8 c7 d8 d8 } 		$a_01_1 = {46 47 42 48 4e 4a 4d 4b 2e 44 4c 4c } 		$a_01_2 = {46 66 67 62 48 67 79 62 68 } 		$a_01_3 = {46 67 62 79 68 6e 4b 6a 67 76 } 		$a_01_4 = {54 74 66 76 79 67 62 4b 68 62 67 66 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=23
 
}