rule Trojan_Win32_RedLineStealer_PB_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {b8 d5 41 1d d4 8b ce f7 e6 8b c6 2b c2 d1 e8 03 c2 c1 e8 05 6b c0 ?? 2b c8 8a 81 ?? ?? ?? ?? 30 04 1e 46 3b f7 72 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}