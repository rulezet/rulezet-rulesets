rule Backdoor_Win32_Lotok_GNP_MTB{
	meta:
		description = "Backdoor:Win32/Lotok.GNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {31 c0 8a 4c 07 01 32 0c 07 89 c2 d1 ea 51 b9 ?? ?? ?? ?? 49 59 83 c0 02 60 89 f9 89 c8 61 88 0c 17 3d } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}