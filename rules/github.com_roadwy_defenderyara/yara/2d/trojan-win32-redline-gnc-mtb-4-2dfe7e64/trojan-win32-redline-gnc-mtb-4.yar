rule Trojan_Win32_Redline_GNC_MTB_4{
	meta:
		description = "Trojan:Win32/Redline.GNC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b d0 88 55 ?? 0f b6 4d ?? 83 c1 ?? 88 4d ?? 0f b6 55 ?? f7 d2 88 55 ?? 0f b6 45 ?? 83 c0 22 88 45 ?? 0f b6 4d ?? f7 d9 88 4d ?? 0f b6 55 ?? 03 55 ?? 88 55 ?? 0f b6 45 ?? f7 d8 88 45 ?? 0f b6 4d } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}