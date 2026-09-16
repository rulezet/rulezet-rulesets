rule Trojan_Win32_Azorult_GKM_MTB{
	meta:
		description = "Trojan:Win32/Azorult.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {14 0f 3d 03 02 00 00 75 06 89 35 84 d1 7f 00 41 3b c8 72 90 09 14 00 8b 15 ?? ?? ?? ?? 8a 94 0a ?? ?? ?? ?? 8b 3d ?? ?? ?? ?? 88 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}