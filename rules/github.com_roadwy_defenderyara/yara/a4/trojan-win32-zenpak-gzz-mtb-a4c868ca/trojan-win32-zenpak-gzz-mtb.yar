rule Trojan_Win32_Zenpak_GZZ_MTB{
	meta:
		description = "Trojan:Win32/Zenpak.GZZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {89 e5 8a 45 ?? 8a 4d ?? 88 0d ?? ?? ?? ?? a2 ?? ?? ?? ?? 30 c8 a2 ?? ?? ?? ?? 0f b6 c0 5d c3 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}