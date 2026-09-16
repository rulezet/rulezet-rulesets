rule Trojan_Win32_Simda_CCIO_MTB{
	meta:
		description = "Trojan:Win32/Simda.CCIO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0f 00 0f 00 07 00 00 "
		
	strings :
		$a_01_0 = {68 65 4c 33 32 } 		$a_01_1 = {68 4b 65 72 4e } 		$a_01_2 = {68 6c 6c 6f 63 } 		$a_01_3 = {68 75 61 6c 41 } 		$a_01_4 = {68 56 69 72 74 } 		$a_01_5 = {66 bb 10 0e 2c 1d ba 9e 00 00 00 8d 8f c0 00 00 00 33 cd } 		$a_01_6 = {33 ca 8f 05 61 2a 41 00 89 55 f4 aa 33 db } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*5+(#a_01_6  & 1)*5) >=15
 
}