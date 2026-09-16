rule Trojan_Win32_SmokeLoader_E_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 0c 24 b8 d1 05 00 00 01 04 24 8b 14 24 8a 04 32 8b 0d ?? ?? ?? ?? 88 04 31 81 c4 04 08 00 00 c3 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}