rule Trojan_Win32_Emotet_GKM_MTB_11{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 f7 f9 8b 44 24 ?? 8a 08 8a 54 14 ?? 32 ca 88 08 40 89 44 24 ?? 8b 44 24 ?? 48 89 44 24 ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}