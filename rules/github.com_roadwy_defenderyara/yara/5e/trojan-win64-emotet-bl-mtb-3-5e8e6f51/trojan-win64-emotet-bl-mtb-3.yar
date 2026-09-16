rule Trojan_Win64_Emotet_BL_MTB_3{
	meta:
		description = "Trojan:Win64/Emotet.BL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 e7 8b cf 4d 8d 49 ?? c1 ea ?? ff c7 6b c2 ?? 2b c8 48 63 c1 42 0f b6 0c 10 41 32 49 ?? 41 88 48 ?? 41 3b fb 7d ?? 4c 8b 15 ?? ?? ?? ?? eb } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}