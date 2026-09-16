rule Trojan_Win32_StealC_EZ_MTB_2{
	meta:
		description = "Trojan:Win32/StealC.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 05 03 cb 89 45 ?? 8b 45 ?? 01 45 ?? 8b fb c1 e7 ?? 03 7d ?? 33 f9 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}