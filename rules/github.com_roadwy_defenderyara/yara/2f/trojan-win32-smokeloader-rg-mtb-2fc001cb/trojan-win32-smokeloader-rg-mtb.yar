rule Trojan_Win32_SmokeLoader_RG_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.RG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {12 a9 31 bb be be 19 16 c8 86 c1 7e 41 35 5f 16 17 be d2 e9 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}