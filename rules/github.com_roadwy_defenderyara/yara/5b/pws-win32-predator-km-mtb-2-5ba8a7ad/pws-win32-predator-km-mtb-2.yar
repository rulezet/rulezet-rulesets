rule PWS_Win32_Predator_KM_MTB_2{
	meta:
		description = "PWS:Win32/Predator.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 ce 89 4d e0 8b ce c1 e9 05 03 4d ?? 89 45 ?? 89 1d ?? ?? ?? ?? 89 1d ?? ?? ?? ?? 8b 45 e0 31 45 fc 81 3d ?? ?? ?? ?? 72 07 00 00 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}