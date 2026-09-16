rule PWS_Win32_Fareit_SM_MTB_6{
	meta:
		description = "PWS:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 f6 89 f6 89 f6 89 f6 8b c1 bb 03 00 00 00 33 d2 f7 f3 85 d2 75 28 89 f6 89 f6 89 f6 8b d6 03 d1 89 f6 89 f6 89 f6 89 f6 b0 29 89 f6 89 f6 89 f6 89 f6 89 f6 30 02 89 f6 89 f6 89 f6 89 f6 89 f6 89 f6 89 f6 41 81 f9 16 1f 01 00 75 b2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}