rule Trojan_Win32_Hancitor_GH_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c8 3b 0d ?? ?? ?? ?? 74 ?? 29 1e 8d 43 ?? 02 c2 66 8b d7 0f b6 c8 66 2b d1 a2 ?? ?? ?? ?? 66 83 ea ?? 0f b7 d2 83 ee ?? 81 fe ?? ?? ?? ?? 7f ?? 8b 44 24 ?? 8b 4c 24 ?? 85 ed 0f 85 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}