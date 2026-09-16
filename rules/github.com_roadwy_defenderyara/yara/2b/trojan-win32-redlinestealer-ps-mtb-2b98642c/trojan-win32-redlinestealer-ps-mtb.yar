rule Trojan_Win32_RedLineStealer_PS_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c3 33 45 f4 33 45 f0 89 45 0c 8b 45 0c 01 05 ?? ?? ?? ?? 8b 45 0c 29 45 fc 8b 4d fc c1 e1 04 03 4d dc 8b 45 fc } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}