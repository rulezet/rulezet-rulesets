rule Backdoor_Win32_Mokes_GNK_MTB_2{
	meta:
		description = "Backdoor:Win32/Mokes.GNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c6 30 08 83 7d 0c 0f ?? ?? 57 ff 75 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}