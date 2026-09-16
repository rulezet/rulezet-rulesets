rule Trojan_Win32_StealC_EZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.EZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e0 ?? 03 45 ?? 33 45 ?? 33 c1 89 45 ?? 8b 45 ?? 29 45 ?? 8b 45 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}