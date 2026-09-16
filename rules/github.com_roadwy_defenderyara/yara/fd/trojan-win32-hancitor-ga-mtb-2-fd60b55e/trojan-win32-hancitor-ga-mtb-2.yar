rule Trojan_Win32_Hancitor_GA_MTB_2{
	meta:
		description = "Trojan:Win32/Hancitor.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 c0 2b d3 8b da 1b c7 8b f8 [0-19] 05 a8 31 04 01 a3 [0-04] 83 c6 ?? 89 02 8a 44 24 ?? 2a 44 24 ?? 2a c3 2c ?? 02 c8 8b c2 83 c0 04 83 6c 24 ?? 01 89 44 24 ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}