rule Trojan_Win32_SmokeLoader_PA_MTB{
	meta:
		description = "Trojan:Win32/SmokeLoader.PA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b c3 c1 e8 ?? c7 05 ?? ?? ?? ?? ?? ?? ?? ?? 89 45 08 8b 45 ?? 01 45 ?? 8b c3 c1 e0 04 03 c6 33 45 08 33 45 0c 50 8d 45 f4 50 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}