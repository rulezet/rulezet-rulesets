rule Backdoor_Win32_Mokes_GXY_MTB{
	meta:
		description = "Backdoor:Win32/Mokes.GXY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {30 0c 33 83 ff 0f ?? ?? 8d 95 ?? ?? ?? ?? 52 6a 00 ff 15 ?? ?? ?? ?? 6a 00 6a 00 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}