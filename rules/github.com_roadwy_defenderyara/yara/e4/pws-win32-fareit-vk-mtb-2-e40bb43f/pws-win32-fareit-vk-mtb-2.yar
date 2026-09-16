rule PWS_Win32_Fareit_VK_MTB_2{
	meta:
		description = "PWS:Win32/Fareit.VK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_02_1 = {8f 04 18 16 17 eb 90 09 03 00 83 c4 } 		$a_02_2 = {31 34 24 68 90 09 03 00 83 c4 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=3
 
}