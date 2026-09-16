rule Adware_Win32_Eorezo{
	meta:
		description = "Adware:Win32/Eorezo,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {61 70 70 50 61 72 74 6e 65 72 22 3a 20 22 65 6f 72 65 7a 6f } 		$a_01_1 = {61 70 70 4e 61 6d 65 22 3a 20 22 74 75 74 6f 34 70 63 } 		$a_01_2 = {63 00 6f 00 6e 00 66 00 2e 00 63 00 79 00 6c 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}