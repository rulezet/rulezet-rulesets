rule Trojan_Win32_Zusy_MA_MTB{
	meta:
		description = "Trojan:Win32/Zusy.MA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,17 00 17 00 05 00 00 "
		
	strings :
		$a_01_0 = {eb 7e d8 ca d8 c3 d8 e7 89 12 d8 d7 d8 cd d8 ce d8 db d8 c0 d8 c0 89 11 d8 ed d8 d9 d8 df d8 c3 d8 d9 d8 e5 d8 c3 d8 ed d8 c1 d8 c4 89 0a d8 c3 } 		$a_01_1 = {46 47 42 48 4e 4a 4d 4b 2e 44 4c 4c } 		$a_01_2 = {46 66 67 62 48 67 79 62 68 } 		$a_01_3 = {46 67 62 79 68 6e 4b 6a 67 76 } 		$a_01_4 = {54 74 66 76 79 67 62 4b 68 62 67 66 } 	condition:
		((#a_01_0  & 1)*10+(#a_01_1  & 1)*10+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=23
 
}