rule Trojan_Win32_RedLineStealer_PU_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 e8 89 44 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 33 44 24 ?? 89 74 24 ?? 89 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 8b 4c 24 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}