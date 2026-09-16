rule Backdoor_Win32_Remcos_MTB{
	meta:
		description = "Backdoor:Win32/Remcos!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 c8 41 f7 e3 c1 ea 02 83 e2 fc 8d 04 92 f7 d8 0f b6 04 06 46 30 87 ?? ?? ?? ?? 47 75 e2 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}