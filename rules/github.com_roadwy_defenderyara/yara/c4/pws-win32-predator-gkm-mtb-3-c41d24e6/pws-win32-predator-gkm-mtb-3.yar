rule PWS_Win32_Predator_GKM_MTB_3{
	meta:
		description = "PWS:Win32/Predator.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 30 0c 1e 83 ff 19 75 ?? 6a 00 6a 00 6a 00 6a 00 ff 15 ?? ?? ?? ?? 55 6a 00 6a 00 ff 15 ?? ?? ?? ?? 46 3b f7 7c } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}