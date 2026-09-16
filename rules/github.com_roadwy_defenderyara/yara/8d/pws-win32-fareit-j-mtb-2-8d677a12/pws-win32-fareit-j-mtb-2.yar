rule PWS_Win32_Fareit_J_MTB_2{
	meta:
		description = "PWS:Win32/Fareit.J!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {85 c0 75 07 b8 01 00 00 00 eb 02 33 c0 90 05 04 01 90 8b 5d ?? 03 de 89 5d ?? 90 05 04 01 90 85 c0 75 ?? 90 05 04 01 90 8a 1a 88 5d ?? 90 05 04 01 90 8b 5d ?? 8b fb 8a 5d ?? 88 1f 90 05 04 01 90 46 90 05 04 01 90 42 49 75 } 		$a_03_1 = {33 c0 5a 59 59 64 89 10 68 ?? ?? ?? ?? c3 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}