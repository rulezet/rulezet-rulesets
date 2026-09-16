rule Trojan_Win32_Redline_GNS_MTB_2{
	meta:
		description = "Trojan:Win32/Redline.GNS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {d1 f9 0f b6 55 ?? c1 e2 ?? 0b ca 88 4d ?? 0f b6 45 ?? 2d ?? ?? ?? ?? 88 45 ?? 0f b6 4d ?? f7 d9 88 4d ?? 0f b6 55 ?? 03 55 ?? 88 55 ?? 8b 45 ?? 8a 4d ?? 88 4c 05 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}