rule Trojan_Win32_Obfuscator_RT_MTB_2{
	meta:
		description = "Trojan:Win32/Obfuscator.RT!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 c0 bb 03 00 a3 ?? ?? ?? ?? c7 45 ?? 00 00 00 00 8b 0d ?? ?? ?? ?? 03 4d ?? 8b 15 ?? ?? ?? ?? 03 55 ?? 3b ca 73 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}