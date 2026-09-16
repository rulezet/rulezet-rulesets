rule Trojan_Win32_Emotet_GKM_MTB_15{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8b 84 24 ?? ?? ?? ?? 8a 08 8a 94 14 ?? ?? ?? ?? 32 ca 88 08 40 89 84 24 ?? ?? ?? ?? 8b 84 24 ?? ?? ?? ?? 48 89 84 24 ?? ?? ?? ?? 0f 85 } 		$a_02_1 = {b9 28 11 00 00 99 f7 f9 8a 5d 00 8b 44 24 ?? 8a 54 14 ?? 32 da 88 5d 00 } 	condition:
		((#a_02_0  & 1)*2+(#a_02_1  & 1)*2) >=2
 
}