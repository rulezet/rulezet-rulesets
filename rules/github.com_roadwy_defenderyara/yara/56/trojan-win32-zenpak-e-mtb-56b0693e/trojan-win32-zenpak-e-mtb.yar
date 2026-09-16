rule Trojan_Win32_Zenpak_E_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.E!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 55 e4 8b 75 c4 8a 0c 32 32 0c 1f 8b 5d e0 88 0c 33 c7 05 ?? ?? ?? ?? 37 22 00 00 81 c6 01 00 00 00 8b 55 f0 39 d6 89 75 c8 0f 84 f3 fe ff ff } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}