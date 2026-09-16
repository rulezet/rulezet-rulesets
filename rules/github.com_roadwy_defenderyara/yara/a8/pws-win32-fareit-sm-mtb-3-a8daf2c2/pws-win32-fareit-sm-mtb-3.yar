rule PWS_Win32_Fareit_SM_MTB_3{
	meta:
		description = "PWS:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b d0 83 e2 01 85 d2 75 0e 8b d3 03 d0 73 05 e8 60 d1 f8 ff 80 32 9c 40 3d bc 18 01 00 75 e1 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}