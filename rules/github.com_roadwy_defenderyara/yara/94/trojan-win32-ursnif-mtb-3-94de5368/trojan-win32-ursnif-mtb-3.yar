rule Trojan_Win32_Ursnif_MTB_3{
	meta:
		description = "Trojan:Win32/Ursnif!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b c2 83 c0 ?? 8b 5c 24 ?? a3 ?? ?? ?? ?? 0f b7 ef 81 c6 ?? ?? ?? ?? 8b c2 2b c5 89 33 83 c3 ?? 83 c0 ?? 83 6c 24 ?? ?? 89 5c 24 ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}