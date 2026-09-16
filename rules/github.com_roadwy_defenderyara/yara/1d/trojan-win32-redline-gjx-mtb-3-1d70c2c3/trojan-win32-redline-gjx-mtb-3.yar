rule Trojan_Win32_Redline_GJX_MTB_3{
	meta:
		description = "Trojan:Win32/Redline.GJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b ca 88 4d ?? 0f b6 45 ?? 03 45 ?? 88 45 ?? 0f b6 4d ?? f7 d1 88 4d ?? 0f b6 55 ?? 33 55 ?? 88 55 ?? 8b 45 ?? 8a 4d ?? 88 4c 05 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}