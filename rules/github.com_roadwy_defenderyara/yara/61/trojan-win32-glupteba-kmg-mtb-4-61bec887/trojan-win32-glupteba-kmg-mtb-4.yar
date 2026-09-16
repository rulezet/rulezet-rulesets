rule Trojan_Win32_Glupteba_KMG_MTB_4{
	meta:
		description = "Trojan:Win32/Glupteba.KMG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {c1 e8 05 89 45 ?? 8b 45 ?? ?? 45 ?? 8b 45 ?? ?? f0 33 f1 81 3d ?? ?? ?? ?? f5 03 00 00 c7 05 ?? ?? ?? ?? 36 06 ea e9 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}