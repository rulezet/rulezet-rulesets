rule PWS_Win32_Fareit_MTB_4{
	meta:
		description = "PWS:Win32/Fareit!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_02_1 = {83 f9 00 7f 90 0a 20 00 09 1c 08 90 0a 50 00 31 f3 90 0a 30 00 8b 1c 0f 90 0a 10 00 49 90 0a 10 00 49 90 0a 10 00 49 90 0a 10 00 49 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}