rule PWS_Win32_Fareit_SF_MTB{
	meta:
		description = "PWS:Win32/Fareit.SF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {68 e0 5e 00 00 [0-05] 59 [0-05] 83 e9 04 [0-05] 8b 1c 0f [0-20] 31 f3 [0-20] 09 1c 08 [0-20] 83 f9 00 7f } 		$a_02_1 = {b9 70 2b 41 41 [0-05] 81 c1 d1 15 00 00 [0-05] 46 [0-20] 8b 1f [0-05] 31 f3 [0-05] 39 cb 75 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}