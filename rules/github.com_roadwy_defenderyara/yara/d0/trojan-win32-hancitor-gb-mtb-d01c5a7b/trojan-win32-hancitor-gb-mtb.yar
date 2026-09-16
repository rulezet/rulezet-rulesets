rule Trojan_Win32_Hancitor_GB_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 f0 0f b7 c3 83 c0 ?? 89 35 ?? ?? ?? ?? 03 45 ?? 8b fe 03 d0 8b 41 ?? 8b da 05 08 36 04 01 2b de 89 41 ?? 83 eb ?? a3 ?? ?? ?? ?? 83 6d ?? 01 75 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}