rule Trojan_Win32_RedLineStealer_RPE_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b f1 8b ce c1 e1 04 03 4d ec 8b c6 c1 e8 05 03 45 e8 03 de 33 cb 33 c8 8d 45 f4 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}