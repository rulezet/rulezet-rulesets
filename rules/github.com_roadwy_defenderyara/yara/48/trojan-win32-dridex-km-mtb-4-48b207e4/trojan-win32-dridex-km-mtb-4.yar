rule Trojan_Win32_Dridex_KM_MTB_4{
	meta:
		description = "Trojan:Win32/Dridex.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {0f be d1 66 89 d6 66 ?? ?? ?? ?? 89 c2 83 c2 01 8a 4c 05 ?? 8a 6d ?? 80 c5 a2 38 e9 88 4d ?? 89 55 ?? 74 ?? eb } 		$a_02_1 = {8a 1c 08 88 1c 0a 83 c1 01 89 4c 24 ?? 8b 44 24 ?? 39 c1 75 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}