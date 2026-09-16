rule Trojan_Win32_RedLineStealer_PD_MTB_2{
	meta:
		description = "Trojan:Win32/RedLineStealer.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c7 33 f0 33 75 ?? 89 75 ?? 8b 45 ?? 01 05 ?? ?? ?? ?? 83 0d ?? ?? ?? ?? ff 2b de 8b c3 c1 e0 04 03 45 ?? 8b d3 89 45 ?? 8d 04 1f 50 8d 45 ?? c1 ea 05 03 55 ?? 50 c7 05 ?? ?? ?? ?? b4 21 e1 c5 e8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}