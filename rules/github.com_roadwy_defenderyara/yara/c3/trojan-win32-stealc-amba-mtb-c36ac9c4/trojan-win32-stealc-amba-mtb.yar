rule Trojan_Win32_StealC_AMBA_MTB{
	meta:
		description = "Trojan:Win32/StealC.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c2 d3 e8 8b 4d ?? 03 c3 33 45 ?? 33 c8 8d 45 ?? 89 4d } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}