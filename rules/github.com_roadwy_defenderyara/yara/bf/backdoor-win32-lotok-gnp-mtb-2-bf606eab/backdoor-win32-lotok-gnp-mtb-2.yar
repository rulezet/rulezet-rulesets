rule Backdoor_Win32_Lotok_GNP_MTB_2{
	meta:
		description = "Backdoor:Win32/Lotok.GNP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 02 00 00 "
		
	strings :
		$a_03_0 = {23 c2 83 c4 ?? a3 ?? ?? ?? ?? 8a 44 24 1c 32 c3 2a c3 32 c3 02 c3 88 04 2f 8b 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 47 03 d1 84 c0 89 15 ?? ?? ?? ?? ?? ?? 8b 54 24 10 8b 44 24 14 83 c6 02 03 d6 3b d0 } 		$a_80_1 = {43 68 37 44 65 6d 64 64 6f 36 } 	condition:
		((#a_03_0  & 1)*10+(#a_80_1  & 1)*1) >=11
 
}