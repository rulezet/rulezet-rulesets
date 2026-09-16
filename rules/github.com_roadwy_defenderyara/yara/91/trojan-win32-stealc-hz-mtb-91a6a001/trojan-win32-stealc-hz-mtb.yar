rule Trojan_Win32_StealC_HZ_MTB{
	meta:
		description = "Trojan:Win32/StealC.HZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e0 ?? 03 45 ?? 8d 0c 1f 33 c1 33 45 ?? 89 45 ?? 8b 45 ?? 29 45 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}