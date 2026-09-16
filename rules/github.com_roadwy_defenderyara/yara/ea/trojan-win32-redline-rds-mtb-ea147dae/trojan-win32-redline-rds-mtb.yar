rule Trojan_Win32_RedLine_RDS_MTB{
	meta:
		description = "Trojan:Win32/RedLine.RDS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d3 ea 8b 4d cc 8d 45 e4 89 7d f4 89 55 e4 e8 ?? ?? ?? ?? 8b 45 e4 33 c7 31 45 e0 89 35 ?? ?? ?? ?? 8b 45 e0 29 45 fc 81 45 e8 ?? ?? ?? ?? ff 4d dc 0f 85 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}