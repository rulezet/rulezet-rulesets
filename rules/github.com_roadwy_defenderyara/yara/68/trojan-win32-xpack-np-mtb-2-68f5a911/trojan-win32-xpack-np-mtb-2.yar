rule Trojan_Win32_XPack_NP_MTB_2{
	meta:
		description = "Trojan:Win32/XPack.NP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_03_0 = {29 c1 89 4c 24 ?? 8b 44 24 30 8b 4c 24 ?? 89 48 54 8b 44 24 ?? 8b 4c 24 30 } 		$a_03_1 = {83 c1 58 81 fa ?? ?? ?? ?? 89 44 24 18 89 4c 24 ?? 72 00 8b 44 24 14 8b 4c 24 ?? 89 08 8b 54 24 } 	condition:
		((#a_03_0  & 1)*3+(#a_03_1  & 1)*3) >=6
 
}