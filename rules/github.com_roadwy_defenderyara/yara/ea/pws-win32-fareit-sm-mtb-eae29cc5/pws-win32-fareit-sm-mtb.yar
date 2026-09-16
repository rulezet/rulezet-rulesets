rule PWS_Win32_Fareit_SM_MTB{
	meta:
		description = "PWS:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a 90 5c 8e 45 00 32 15 f8 2c 46 00 90 90 90 8b c7 03 c3 90 90 8b f0 90 8b c6 e8 8d fd ff ff 90 90 90 90 90 43 81 fb 12 5b 00 00 75 } 		$a_03_1 = {89 f6 89 f6 89 f6 8b c1 be 03 00 00 00 33 d2 f7 f6 85 d2 75 1e 89 f6 89 f6 8b c3 03 c1 73 05 e8 4f af f9 ff 89 f6 89 f6 89 f6 89 f6 89 f6 80 30 [0-04] 89 f6 89 f6 41 81 f9 [0-04] 75 c2 } 	condition:
		((#a_00_0  & 1)*2+(#a_03_1  & 1)*1) >=2
 
}