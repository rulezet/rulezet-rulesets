rule Trojan_Win32_Dridex_GD_MTB{
	meta:
		description = "Trojan:Win32/Dridex.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a 14 01 8b 75 ?? 88 14 06 83 c0 ?? 89 45 ?? 8b 7d ?? 39 f8 90 13 [0-20] 8b 45 ?? 8b 4d } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}