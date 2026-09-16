rule Trojan_Win32_Gozi_GR_MTB{
	meta:
		description = "Trojan:Win32/Gozi.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b7 d0 83 c0 ?? 0f b7 c0 89 45 ?? 0f b7 c0 2b c7 89 55 ?? 83 c0 ?? a3 ?? ?? ?? ?? 0f b6 c1 03 c0 2b c6 05 ?? ?? ?? ?? a3 ?? ?? ?? ?? ff 15 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}