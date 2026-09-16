rule PWS_Win32_Fareit_A_MTB_3{
	meta:
		description = "PWS:Win32/Fareit.A!MTB,SIGNATURE_TYPE_PEHSTR,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {8a 02 90 90 90 34 dd 88 45 fb 90 90 90 90 90 8b 4d fc 8a 45 fb 88 01 90 8b 45 f4 40 89 45 f4 90 90 90 ff 45 f0 42 81 7d } 		$a_01_1 = {4d 71 62 69 32 57 46 65 79 66 31 } 		$a_01_2 = {50 6f 6e 5a 50 74 41 4a 30 6a 48 45 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}