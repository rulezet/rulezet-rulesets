rule PWS_Win32_Fareit_VK_MTB_3{
	meta:
		description = "PWS:Win32/Fareit.VK!MTB,SIGNATURE_TYPE_PEHSTR,06 00 06 00 06 00 00 "
		
	strings :
		$a_01_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_01_1 = {5f 8b 10 53 } 		$a_01_2 = {5b 31 f2 57 } 		$a_01_3 = {5f 89 10 57 } 		$a_01_4 = {8b 9c 24 1c 01 00 00 } 		$a_01_5 = {8b 94 24 20 01 00 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1+(#a_01_4  & 1)*1+(#a_01_5  & 1)*1) >=6
 
}