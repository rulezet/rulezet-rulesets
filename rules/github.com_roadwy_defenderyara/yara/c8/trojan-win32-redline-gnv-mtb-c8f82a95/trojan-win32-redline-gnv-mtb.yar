rule Trojan_Win32_Redline_GNV_MTB{
	meta:
		description = "Trojan:Win32/Redline.GNV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {0f b6 0e 83 c4 ?? 0f b6 07 8b 74 24 ?? 03 c8 0f b6 c1 8a 84 04 ?? ?? ?? ?? 30 85 ?? ?? ?? ?? 45 81 fd ?? ?? ?? ?? 0f 82 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}