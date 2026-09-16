rule PWS_Win32_Predator_KM_MTB_3{
	meta:
		description = "PWS:Win32/Predator.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 85 ?? ?? ?? ?? ?? 45 ?? 33 d2 81 3d ?? ?? ?? ?? 12 09 00 00 75 } 		$a_00_1 = {8a 04 0e 88 04 11 41 3b cb 72 } 	condition:
		((#a_02_0  & 1)*1+(#a_00_1  & 1)*1) >=2
 
}