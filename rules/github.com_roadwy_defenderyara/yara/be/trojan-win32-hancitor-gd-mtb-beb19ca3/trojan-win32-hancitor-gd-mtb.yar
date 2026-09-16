rule Trojan_Win32_Hancitor_GD_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 11 88 10 8b 45 ?? 83 c0 01 89 45 ?? 8b 4d ?? 83 c1 01 89 4d ?? 8b 15 ?? ?? ?? ?? 83 ea ?? 33 c0 2b 55 ?? 1b 45 ?? 89 55 ?? eb } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}