rule PWS_Win32_Fareit_SM_MTB_5{
	meta:
		description = "PWS:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 f6 89 f6 89 f6 8b c1 be 03 00 00 00 33 d2 f7 f6 85 d2 75 1e 89 f6 89 f6 8b c3 03 c1 73 05 e8 4f af f9 ff 89 f6 89 f6 89 f6 89 f6 89 f6 80 30 27 89 f6 89 f6 41 81 f9 a1 f7 00 00 75 c2 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}