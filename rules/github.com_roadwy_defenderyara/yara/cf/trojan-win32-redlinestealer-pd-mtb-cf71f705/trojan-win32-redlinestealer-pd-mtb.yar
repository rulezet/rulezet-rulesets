rule Trojan_Win32_RedLineStealer_PD_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 45 0c 8b 45 ec 01 45 0c 8b 45 e8 83 25 ?? ?? ?? ?? ?? 03 c8 8d 04 3b 33 c8 31 4d 0c 8b 45 0c 01 05 ?? ?? ?? ?? 2b 75 0c 83 0d ?? ?? ?? ?? ?? 8b c6 c1 e8 ?? 03 45 f4 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}