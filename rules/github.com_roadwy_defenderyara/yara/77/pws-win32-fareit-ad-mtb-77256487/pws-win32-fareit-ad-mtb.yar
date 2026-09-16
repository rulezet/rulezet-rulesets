rule PWS_Win32_Fareit_AD_MTB{
	meta:
		description = "PWS:Win32/Fareit.AD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {59 ff 34 0e bb ?? ?? ?? ?? 5a 31 da 89 14 08 90 05 30 03 d9 d0 90 83 e9 04 7d ?? ff e0 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}