rule Trojan_Win32_Obfuscator_BO_MTB_2{
	meta:
		description = "Trojan:Win32/Obfuscator.BO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {2b d1 8d 4c 32 f7 81 c7 ?? ?? ?? ?? 89 7d 00 0f b6 2d ?? ?? ?? ?? 0f b6 15 ?? ?? ?? ?? 8b f5 2b f2 81 fe ?? ?? ?? ?? 75 16 8b d1 2b d0 83 ea ?? 83 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}