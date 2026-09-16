rule Trojan_Win32_KeyLogger_PABZ_MTB{
	meta:
		description = "Trojan:Win32/KeyLogger.PABZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 05 00 00 "
		
	strings :
		$a_01_0 = {42 6f 74 20 73 74 61 72 74 65 64 } 		$a_01_1 = {56 69 72 75 73 } 		$a_01_2 = {23 73 70 61 6d } 		$a_01_3 = {4b 4f 53 4f 4d 41 4b 59 34 44 } 		$a_01_4 = {56 72 58 2d 20 42 6f 74 20 49 44 3a 20 25 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1) >=5
 
}