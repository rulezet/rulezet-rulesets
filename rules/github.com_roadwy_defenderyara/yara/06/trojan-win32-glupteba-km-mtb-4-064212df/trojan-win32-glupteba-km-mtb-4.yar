rule Trojan_Win32_Glupteba_KM_MTB_4{
	meta:
		description = "Trojan:Win32/Glupteba.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 44 24 ?? 8b 84 24 ?? ?? ?? ?? 01 44 24 ?? 8b 8c 24 ?? ?? ?? ?? 03 f1 8d 14 2f 33 f2 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}