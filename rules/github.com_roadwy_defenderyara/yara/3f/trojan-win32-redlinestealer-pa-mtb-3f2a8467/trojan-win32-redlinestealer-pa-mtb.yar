rule Trojan_Win32_RedLineStealer_PA_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 75 ec 8b 45 e8 01 45 ec 8b 45 e4 01 45 ec 8b 45 ec 89 45 f4 8b 45 e4 8b 4d f0 d3 e8 89 45 fc 8b 45 cc 01 45 fc 8b 5d e4 c1 e3 ?? 03 5d d8 33 5d f4 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}