rule Trojan_Win32_Emotet_GKM_MTB_8{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 b9 96 16 00 00 f7 f9 8b 44 24 ?? 83 c0 01 8b ce 89 44 24 ?? 0f b6 94 14 ?? ?? ?? ?? 30 50 ff } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}