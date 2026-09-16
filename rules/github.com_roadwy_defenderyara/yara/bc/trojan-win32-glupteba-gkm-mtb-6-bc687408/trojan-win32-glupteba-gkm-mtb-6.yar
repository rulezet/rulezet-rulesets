rule Trojan_Win32_Glupteba_GKM_MTB_6{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 8d 0c 38 89 54 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b f7 c1 e6 04 03 b4 24 ?? ?? ?? ?? c7 05 ?? ?? ?? ?? 36 06 ea e9 33 f1 81 3d ?? ?? ?? ?? f5 03 00 00 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}