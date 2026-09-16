rule PWS_Win32_Fareit_G_MTB_2{
	meta:
		description = "PWS:Win32/Fareit.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {ff 34 0e 81 34 24 ?? ?? ?? ?? 8f 04 08 c3 } 		$a_02_1 = {00 00 59 83 e9 04 e8 ?? ff ff ff 83 e9 03 e0 f6 e8 ?? ff ff ff ff e0 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}