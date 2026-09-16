rule Trojan_Win32_StealC_AZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.AZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d7 c1 e2 ?? 03 55 ?? 33 55 ?? 33 d1 89 55 ?? 8b 45 ?? 29 45 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}