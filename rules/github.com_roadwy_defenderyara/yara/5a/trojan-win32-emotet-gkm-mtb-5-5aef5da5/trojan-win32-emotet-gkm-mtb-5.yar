rule Trojan_Win32_Emotet_GKM_MTB_5{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c9 03 c1 99 b9 21 d8 00 00 f7 f9 8a 45 00 8d 4c 24 ?? 8a 9c 14 ?? ?? ?? ?? 32 d8 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}