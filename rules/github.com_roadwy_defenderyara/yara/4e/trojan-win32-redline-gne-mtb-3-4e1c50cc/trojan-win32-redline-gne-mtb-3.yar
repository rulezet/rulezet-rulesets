rule Trojan_Win32_Redline_GNE_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GNE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {f7 d2 88 55 ?? 0f b6 45 ?? 83 c0 ?? 88 45 ?? 0f b6 4d ?? f7 d1 88 4d ?? 0f b6 55 ?? d1 fa 0f b6 45 ?? c1 e0 ?? 0b d0 88 55 ?? 8b 4d ?? 8a 55 ?? 88 54 0d } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}