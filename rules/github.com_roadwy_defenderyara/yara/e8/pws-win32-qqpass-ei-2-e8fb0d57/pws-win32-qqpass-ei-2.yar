rule PWS_Win32_QQpass_EI_2{
	meta:
		description = "PWS:Win32/QQpass.EI,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 04 00 00 "
		
	strings :
		$a_01_0 = {63 3a 5c 32 2e 6a 70 67 } 		$a_01_1 = {6a 7a 79 71 66 68 64 73 6c 69 6e 62 63 } 		$a_01_2 = {26 51 51 50 61 73 73 57 6f 72 64 3d 00 3f 51 51 4e 75 6d 62 65 72 3d 00 } 		$a_01_3 = {31 31 31 30 2f 32 68 67 68 66 2f 6d 61 69 6c 2e 61 73 70 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1+(#a_01_3  & 1)*1) >=4
 
}