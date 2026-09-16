rule PWS_Win32_Fareit_AD_MTB_3{
	meta:
		description = "PWS:Win32/Fareit.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {83 f9 00 7f 90 0a ff 00 49 [0-08] 49 [0-08] 49 [0-08] 49 [0-10] ff 34 0f [0-30] 31 34 24 [0-30] 8f 04 08 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}