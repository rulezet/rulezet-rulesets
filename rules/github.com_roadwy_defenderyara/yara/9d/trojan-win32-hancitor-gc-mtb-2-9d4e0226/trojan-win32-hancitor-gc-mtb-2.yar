rule Trojan_Win32_Hancitor_GC_MTB_2{
	meta:
		description = "Trojan:Win32/Hancitor.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 89 45 fc eb ?? 0f b6 0d ?? ?? ?? ?? 8b 15 ?? ?? ?? ?? 8d 44 11 ?? a3 ?? ?? ?? ?? 0f b7 4d fc 0f af 0d ?? ?? ?? ?? 03 4d 0c 66 89 4d fc 8b 75 f4 41 83 c6 03 2b c8 83 ee 03 83 c1 71 ff e6 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}