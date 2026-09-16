rule PWS_Win32_Predator_GKM_MTB_2{
	meta:
		description = "PWS:Win32/Predator.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {69 c0 fd 43 03 00 05 c3 9e 26 00 a3 ?? ?? ?? ?? 8a 0d ?? ?? ?? ?? 30 0c 37 83 fb 19 75 ?? 6a 00 8d 54 24 ?? 52 6a 00 6a 00 6a 00 6a 00 ff 15 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}