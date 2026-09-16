rule Trojan_Win32_Dridex_GC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 14 01 8b 75 ?? 88 14 06 83 c0 ?? 89 45 ?? 66 c7 45 [0-20] 66 81 7d [0-20] 8b 45 ?? 8b 4d ?? 89 4d ?? 8b 4d ?? 39 c8 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}