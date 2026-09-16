rule Trojan_Win32_Gozi_GR_MTB_2{
	meta:
		description = "Trojan:Win32/Gozi.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 2b c3 fe c1 66 83 c0 ?? 02 c9 66 03 f8 8b 44 24 ?? 2a c8 2a cb 8a c1 c0 e1 ?? 02 c1 8b 4c 24 ?? 02 d0 8b 44 24 ?? 88 15 ?? ?? ?? ?? 85 c0 75 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}