rule Trojan_Win32_Ursnif_AG_MTB_2{
	meta:
		description = "Trojan:Win32/Ursnif.AG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {8b 5c 24 10 8b 1b 8b c8 2b ce 83 e9 04 83 ef 04 89 1d ?? ?? ?? 00 81 fe } 		$a_02_1 = {8b 54 24 10 8d 4c 06 41 a1 ?? ?? ?? 00 05 ?? ?? ?? ?? 89 02 0f b6 15 ?? ?? ?? 00 a3 ?? ?? ?? 00 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}