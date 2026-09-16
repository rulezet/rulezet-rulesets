rule Trojan_Win32_SmokeLoader_RG_MTB_5{
	meta:
		description = "Trojan:Win32/SmokeLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {c1 e0 04 89 45 ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 8b 4d ?? 8d 14 03 d3 e8 03 45 ?? 33 c2 31 45 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}