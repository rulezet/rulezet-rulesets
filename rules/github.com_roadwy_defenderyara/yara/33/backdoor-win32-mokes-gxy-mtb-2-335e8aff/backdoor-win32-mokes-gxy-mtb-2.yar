rule Backdoor_Win32_Mokes_GXY_MTB_2{
	meta:
		description = "Backdoor:Win32/Mokes.GXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {56 69 72 74 66 c7 05 ?? ?? ?? ?? 6f 74 c7 05 ?? ?? ?? ?? 75 61 6c 50 c7 05 ?? ?? ?? ?? 65 63 74 00 c6 05 ?? ?? ?? ?? 72 ff 15 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}