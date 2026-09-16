rule Trojan_Win32_Gozi_GM_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {66 2b d0 0f b7 c2 8b 55 ?? 89 45 ?? 0f b7 75 ?? 8d 42 ?? 02 c8 8d 04 b7 88 0d ?? ?? ?? ?? 03 c6 a3 ?? ?? ?? ?? 0f b6 c1 2b c2 83 c0 ?? 89 45 ?? ff 15 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}