rule Trojan_Win32_RedLineStealer_RPY_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.RPY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {f6 17 33 f3 33 c0 33 db 33 c6 8b f3 33 c6 8b f3 8b f0 8b d8 80 07 75 33 f0 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}