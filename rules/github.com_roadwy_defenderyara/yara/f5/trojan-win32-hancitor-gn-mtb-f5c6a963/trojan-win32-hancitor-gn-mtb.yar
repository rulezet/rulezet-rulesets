rule Trojan_Win32_Hancitor_GN_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 04 52 03 c0 2b 45 ?? 2b 45 ?? 03 c2 0f b7 f0 6b c6 ?? 89 45 ?? 03 c1 0f b7 f8 0f b6 05 ?? ?? ?? ?? 83 c0 ?? a3 ?? ?? ?? ?? ff 15 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}