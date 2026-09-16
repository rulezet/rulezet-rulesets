rule Trojan_Win32_Hancitor_GC_MTB{
	meta:
		description = "Trojan:Win32/Hancitor.GC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 45 08 0f b7 c1 ff 75 08 8d 94 00 ?? ?? ?? ?? a0 ?? ?? ?? ?? 66 0f b6 c8 66 2b d1 8b 0d ?? ?? ?? ?? 04 01 f6 e9 66 03 d1 0f b7 d2 a2 ?? ?? ?? ?? c3 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}