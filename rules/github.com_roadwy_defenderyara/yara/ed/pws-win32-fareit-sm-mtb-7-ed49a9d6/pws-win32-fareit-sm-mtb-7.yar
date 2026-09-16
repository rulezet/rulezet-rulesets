rule PWS_Win32_Fareit_SM_MTB_7{
	meta:
		description = "PWS:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {83 7d e8 00 76 30 8b 45 e8 83 e0 03 85 c0 75 15 8b 45 e8 8a 80 88 80 46 00 34 71 8b 55 fc 03 55 e8 88 02 eb 11 8b 45 e8 8a 80 88 80 46 00 8b 55 fc 03 55 e8 88 02 ff 45 e8 81 7d e8 22 83 00 00 75 be } 		$a_01_1 = {85 c0 76 20 8b c8 83 e1 03 85 c9 75 0e 8a 0a 80 f1 f5 8b 5d fc 03 d8 88 0b eb 09 8b 4d fc 03 c8 8a 1a 88 19 40 42 3d a1 7c 00 00 75 d3 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}