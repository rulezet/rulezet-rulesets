rule PWS_Win32_Fareit_MTB_6{
	meta:
		description = "PWS:Win32/Fareit!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {4d 53 56 42 56 4d 36 30 2e 44 4c 4c } 		$a_02_1 = {83 c7 04 85 90 0a ff 00 83 c2 04 90 0a ff 00 83 c4 04 90 0a ff 00 89 0c 18 90 0a ff 00 8b 0c 24 90 0a ff 00 31 34 24 90 0a ff 00 ff 37 } 		$a_02_2 = {83 c7 04 66 90 0a ff 00 83 c2 04 90 0a ff 00 83 c4 04 90 0a ff 00 89 0c 18 90 0a ff 00 8b 0c 24 90 0a ff 00 31 34 24 90 0a ff 00 ff 37 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1+(#a_02_2  & 1)*1) >=2
 
}