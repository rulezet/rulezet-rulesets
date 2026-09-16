rule Trojan_Win32_Emotet_GKM_MTB_3{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {99 b9 5c af 00 00 f7 f9 8a 5d 00 8d 4c 24 ?? 8a 94 14 ?? ?? ?? ?? 32 da 88 5d 00 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}