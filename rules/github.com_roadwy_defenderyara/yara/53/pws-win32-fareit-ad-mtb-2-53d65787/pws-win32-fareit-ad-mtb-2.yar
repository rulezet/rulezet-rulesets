rule PWS_Win32_Fareit_AD_MTB_2{
	meta:
		description = "PWS:Win32/Fareit.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {6a 40 68 00 10 00 00 68 ?? ?? ?? ?? 6a 00 ff d0 90 0a 25 00 a1 ?? ?? ?? ?? 48 66 81 38 4d 5a 75 f8 05 ?? ?? ?? ?? 8b 00 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}