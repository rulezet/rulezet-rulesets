rule Trojan_Win32_Obfuscator_EO_MTB{
	meta:
		description = "Trojan:Win32/Obfuscator.EO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 4d 17 0f b6 03 03 c1 99 8b cf f7 f9 8b 85 ?? ?? ?? ?? 83 4d fc ff 8a 8c 15 ?? ?? ?? ?? 30 08 40 8d 8d ?? ?? ?? ?? 89 85 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}