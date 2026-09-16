rule Trojan_Win32_Redline_GKK_MTB{
	meta:
		description = "Trojan:Win32/Redline.GKK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 84 3c ?? ?? ?? ?? 03 c6 59 8b 4c 24 ?? 0f b6 c0 8a 84 04 ?? ?? ?? ?? 30 81 ?? ?? ?? ?? 41 89 4c 24 ?? 81 f9 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}