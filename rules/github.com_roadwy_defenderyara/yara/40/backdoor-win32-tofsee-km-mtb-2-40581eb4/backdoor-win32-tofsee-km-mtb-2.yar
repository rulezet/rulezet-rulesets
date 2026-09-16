rule Backdoor_Win32_Tofsee_KM_MTB_2{
	meta:
		description = "Backdoor:Win32/Tofsee.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {d3 e2 89 5c 24 ?? 89 54 24 ?? 8b 44 24 ?? ?? 44 24 0c 8b 44 24 ?? ?? 44 24 0c 8b 44 24 ?? 8b 0d ?? ?? ?? ?? 03 c6 81 f9 72 05 00 00 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}