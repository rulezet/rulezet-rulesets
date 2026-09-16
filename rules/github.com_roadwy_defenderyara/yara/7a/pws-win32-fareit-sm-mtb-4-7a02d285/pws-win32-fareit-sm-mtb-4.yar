rule PWS_Win32_Fareit_SM_MTB_4{
	meta:
		description = "PWS:Win32/Fareit.SM!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {bb 01 00 00 00 90 90 90 90 8b c2 03 c3 90 90 90 c6 00 94 90 90 90 90 43 81 fb 7f 2f 4b 22 75 e5 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}