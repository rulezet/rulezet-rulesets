rule Trojan_Win32_Raccoon_RB_MTB_4{
	meta:
		description = "Trojan:Win32/Raccoon.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c8 c1 e1 04 03 4c 24 ?? 89 4c 24 ?? 8d 0c 07 c1 e8 05 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 c1 33 44 24 [0-12] 2b f0 89 44 24 ?? 8b c6 c1 e0 04 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}