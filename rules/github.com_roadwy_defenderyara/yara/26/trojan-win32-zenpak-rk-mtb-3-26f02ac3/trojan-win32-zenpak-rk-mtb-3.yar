rule Trojan_Win32_Zenpak_RK_MTB_3{
	meta:
		description = "Trojan:Win32/Zenpak.RK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b 75 08 88 45 ?? 89 4d ?? 89 55 ?? 89 75 ?? 8b 4d ?? 8b 55 ?? 0f b6 0c ?? 0f b6 55 ?? 29 d1 88 c8 88 45 fb 8a 45 fb 8b 4d f4 8b 55 e8 88 04 0a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}