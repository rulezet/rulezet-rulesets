rule Trojan_Win32_Fareit_VB_MTB_3{
	meta:
		description = "Trojan:Win32/Fareit.VB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_01_1 = {72 00 36 00 79 00 70 00 54 00 62 00 6a 00 6c 00 48 00 65 00 59 00 62 00 5a 00 66 00 42 00 76 00 79 00 35 00 37 00 } 		$a_01_2 = {51 00 57 00 41 00 42 00 41 00 4b 00 66 00 79 00 35 00 33 00 } 	condition:
		((#a_00_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}