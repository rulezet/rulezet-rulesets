rule Trojan_Win32_RedLineStealer_PT_MTB{
	meta:
		description = "Trojan:Win32/RedLineStealer.PT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e8 05 c7 05 ?? ?? ?? ?? 19 36 6b ff 89 45 08 8b 45 e4 01 45 08 8b 45 08 33 45 0c 33 c8 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}