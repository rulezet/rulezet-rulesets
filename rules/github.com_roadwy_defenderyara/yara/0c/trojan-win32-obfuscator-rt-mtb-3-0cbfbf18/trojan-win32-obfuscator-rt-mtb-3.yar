rule Trojan_Win32_Obfuscator_RT_MTB_3{
	meta:
		description = "Trojan:Win32/Obfuscator.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f be 08 81 f1 80 00 00 00 88 ?? ?? 8b ?? ?? 03 ?? ?? 89 55 ?? 8b 45 ?? 3b 45 ?? 73 ?? 8b 4d ?? 0f b6 11 0f b6 45 ?? 33 d0 8b 4d ?? 2b 4d ?? 0f b6 c1 25 80 00 00 00 33 d0 8b 4d ?? 88 11 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}