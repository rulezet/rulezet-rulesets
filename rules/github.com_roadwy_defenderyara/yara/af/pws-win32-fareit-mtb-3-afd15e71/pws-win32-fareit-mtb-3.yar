rule PWS_Win32_Fareit_MTB_3{
	meta:
		description = "PWS:Win32/Fareit!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_02_1 = {83 fb 00 7f 90 0a c0 00 83 eb 04 [0-20] ff 34 1f [0-20] 8f 04 18 [0-20] 31 34 18 } 	condition:
		((#a_01_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}