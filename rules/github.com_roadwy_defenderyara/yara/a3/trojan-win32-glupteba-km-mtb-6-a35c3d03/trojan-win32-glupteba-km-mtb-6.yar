rule Trojan_Win32_Glupteba_KM_MTB_6{
	meta:
		description = "Trojan:Win32/Glupteba.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {8a 14 06 88 14 38 40 3b c1 72 } 		$a_02_1 = {c1 ea 05 89 54 24 ?? c7 05 ?? ?? ?? ?? 2e ce 50 91 8b 84 24 ?? ?? ?? ?? ?? 44 24 ?? 81 3d ?? ?? ?? ?? 12 09 00 00 75 } 	condition:
		((#a_00_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}