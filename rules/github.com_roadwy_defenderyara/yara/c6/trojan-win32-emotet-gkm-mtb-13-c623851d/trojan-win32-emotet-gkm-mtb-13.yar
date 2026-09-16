rule Trojan_Win32_Emotet_GKM_MTB_13{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8b 44 24 ?? 8b 8c 24 ?? ?? ?? ?? 8a 54 14 ?? 30 14 08 40 89 44 24 ?? 8b 84 24 ?? ?? ?? ?? 8b c8 48 85 c9 89 84 24 ?? ?? ?? ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*2) >=2
 
}