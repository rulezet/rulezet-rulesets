rule Trojan_Win32_Obfuscator_DB_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.DB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b 4d f4 8b d7 d3 e2 8b 4d f0 8b c7 c1 e8 05 03 55 e4 03 45 e0 03 cf 33 d0 33 d1 8b 0d ?? ?? ?? ?? 29 55 f8 c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 81 f9 ?? ?? ?? ?? 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}