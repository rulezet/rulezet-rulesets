rule Trojan_Win32_Emotet_GKM_MTB_7{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 b9 e5 08 00 00 f7 f9 8b 4c 24 ?? 8b 84 24 ?? ?? ?? ?? 8a 1c 01 8a 54 14 ?? 32 da 88 1c 01 } 	condition:
		((#a_02_0  & 1)*2) >=2
 
}