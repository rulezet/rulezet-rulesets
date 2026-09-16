rule Trojan_Win32_Obfuscator_YY_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.YY!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b f0 03 75 fc 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 03 f0 68 ?? ?? ?? ?? ff 15 ?? ?? ?? ?? 03 f0 8b 4d 08 03 31 8b 55 08 89 32 5e 8b e5 5d c3 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}