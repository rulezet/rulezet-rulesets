rule PWS_Win32_Fareit_C_MTB{
	meta:
		description = "PWS:Win32/Fareit.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {8b cf b2 59 8a 03 90 18 32 c2 88 01 c3 } 		$a_01_1 = {47 43 4e 75 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}