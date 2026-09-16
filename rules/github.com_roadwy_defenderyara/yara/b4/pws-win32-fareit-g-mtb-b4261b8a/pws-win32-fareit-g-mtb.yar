rule PWS_Win32_Fareit_G_MTB{
	meta:
		description = "PWS:Win32/Fareit.G!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8a 00 c3 53 8b d8 6a 00 e8 ?? ?? ?? ?? 90 90 90 90 8b c3 34 ?? 90 90 90 90 5b c3 53 56 57 55 51 8b da 8b f0 54 6a 40 68 ?? ?? ?? ?? 56 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}