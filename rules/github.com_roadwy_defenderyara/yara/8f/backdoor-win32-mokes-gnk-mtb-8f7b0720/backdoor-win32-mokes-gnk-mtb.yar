rule Backdoor_Win32_Mokes_GNK_MTB{
	meta:
		description = "Backdoor:Win32/Mokes.GNK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 08 59 8a 4d fc 03 c3 30 08 83 7d 0c 0f } 	condition:
		((#a_01_0  & 1)*10) >=10
 
}