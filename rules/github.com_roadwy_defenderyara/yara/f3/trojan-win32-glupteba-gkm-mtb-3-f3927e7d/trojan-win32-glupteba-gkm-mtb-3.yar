rule Trojan_Win32_Glupteba_GKM_MTB_3{
	meta:
		description = "Trojan:Win32/Glupteba.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 ea 05 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 03 f0 8d 0c 2f 33 f1 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}