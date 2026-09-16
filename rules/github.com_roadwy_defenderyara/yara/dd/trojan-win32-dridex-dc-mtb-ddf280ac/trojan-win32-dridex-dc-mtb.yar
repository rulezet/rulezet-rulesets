rule Trojan_Win32_Dridex_DC_MTB{
	meta:
		description = "Trojan:Win32/Dridex.DC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 c7 66 01 05 ?? ?? ?? ?? 8d 04 3f 2b c8 0f b7 c3 2b c6 89 0d ?? ?? ?? ?? 8b 4c 24 18 83 c0 06 a3 ?? ?? ?? ?? 8b 44 24 14 05 24 73 02 01 a3 ?? ?? ?? ?? 89 01 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}