rule PWS_Win32_Predator_GKM_MTB{
	meta:
		description = "PWS:Win32/Predator.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 03 44 24 ?? 33 d0 89 1d ?? ?? ?? ?? 8d 04 3e 33 d0 2b ea 8b 15 ?? ?? ?? ?? 81 fa d5 01 00 00 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}