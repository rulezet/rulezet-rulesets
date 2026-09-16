rule Trojan_Win32_Amadey_BSA_MTB_2{
	meta:
		description = "Trojan:Win32/Amadey.BSA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 08 00 00 "
		
	strings :
		$a_01_0 = {eb 08 0f dc 2d 00 00 00 00 00 e9 } 		$a_01_1 = {eb 08 0f 24 2e 00 00 00 00 00 e9 } 		$a_01_2 = {eb 08 0f 22 2e 00 00 00 00 00 e9 } 		$a_01_3 = {eb 08 0f 48 2d 00 00 00 00 00 e9 } 		$a_01_4 = {eb 08 0f 28 2d 00 00 00 00 00 e9 } 		$a_01_5 = {eb 08 0f fc 2c 00 00 00 00 00 e9 } 		$a_01_6 = {eb 08 0f ee 2c 00 00 00 00 00 e9 } 		$a_01_7 = {eb 08 0f 4a 2b 00 00 00 00 00 e9 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1+(#a_01_6  & 1)*1+(#a_01_7  & 1)*1) >=1
 
}