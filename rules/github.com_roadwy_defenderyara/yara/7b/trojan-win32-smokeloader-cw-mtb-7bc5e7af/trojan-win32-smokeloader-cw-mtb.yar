rule Trojan_Win32_SmokeLoader_CW_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.CW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 ?? 03 45 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 33 45 ?? 31 45 ?? 2b 75 ?? ff 4d ?? 0f 85 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}