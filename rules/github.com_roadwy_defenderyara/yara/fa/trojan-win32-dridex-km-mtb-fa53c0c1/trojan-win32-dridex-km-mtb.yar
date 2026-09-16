rule Trojan_Win32_Dridex_KM_MTB{
	meta:
		description = "Trojan:Win32/Dridex.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c3 05 e2 38 00 00 03 c6 8d 0c 48 0f b6 05 ?? ?? ?? ?? 89 0d ?? ?? ?? ?? 3b f0 74 ?? a0 ?? ?? ?? ?? 83 c2 02 83 fa 0d 7c } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}