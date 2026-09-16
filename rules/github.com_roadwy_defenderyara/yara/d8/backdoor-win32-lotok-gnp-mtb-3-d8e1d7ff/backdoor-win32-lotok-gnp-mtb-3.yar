rule Backdoor_Win32_Lotok_GNP_MTB_3{
	meta:
		description = "Backdoor:Win32/Lotok.GNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {33 c0 b2 72 f2 ae f7 d1 49 88 54 24 ?? 88 54 24 ?? 8b d1 bf ?? ?? ?? ?? 83 c9 ff f2 ae f7 d1 49 c6 44 24 ?? 43 c6 44 24 ?? 74 c6 44 24 ?? 54 8d 44 0a ?? c6 44 24 ?? 68 50 c6 44 24 ?? 64 c6 44 24 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}