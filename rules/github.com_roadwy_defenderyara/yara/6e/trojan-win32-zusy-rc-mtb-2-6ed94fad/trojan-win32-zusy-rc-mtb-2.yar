rule Trojan_Win32_Zusy_RC_MTB_2{
	meta:
		description = "Trojan:Win32/Zusy.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 04 00 00 "
		
	strings :
		$a_03_0 = {6a 02 6a 00 6a 02 e8 ?? ?? fe ff 6a 02 6a 00 6a 02 e8 ?? ?? fe ff 6a 02 6a 00 6a 02 e8 ?? ?? fe ff } 		$a_01_1 = {6a 68 53 37 68 34 48 73 59 33 67 68 36 35 68 73 57 33 33 33 34 } 		$a_01_2 = {43 43 43 20 43 72 79 70 74 65 72 } 		$a_01_3 = {58 45 41 5a 45 52 54 41 43 51 } 	condition:
		((#a_03_0  & 1)*5+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=8
 
}