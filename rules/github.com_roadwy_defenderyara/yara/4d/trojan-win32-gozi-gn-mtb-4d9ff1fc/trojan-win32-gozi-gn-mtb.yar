rule Trojan_Win32_Gozi_GN_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0a 00 02 00 00 "
		
	strings :
		$a_02_0 = {33 c9 03 c0 03 d0 8b c2 8a 35 ?? ?? ?? ?? 13 f9 02 f0 4e 88 35 ?? ?? ?? ?? 0f af f0 8b 4c 24 ?? 8a d3 8b 09 89 4c 24 ?? 8a cb c0 e1 ?? 02 d1 02 d0 88 15 ?? ?? ?? ?? 3b 1d ?? ?? ?? ?? 72 ?? 8d 4b ?? 02 f0 03 c8 88 35 } 		$a_00_1 = {f3 a4 8b 44 24 0c 5e 5f c3 } 	condition:
		((#a_02_0  & 1)*10+(#a_00_1  & 1)*1) >=10
 
}