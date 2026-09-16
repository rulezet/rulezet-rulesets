rule Trojan_Win32_Emotet_GKM_MTB_14{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 20 04 00 00 f7 f9 8a 5d 00 8b 44 24 ?? 8a 54 14 ?? 32 da 88 5d 00 } 		$a_02_1 = {03 c1 99 b9 20 04 00 00 f7 f9 45 0f b6 54 14 ?? 30 55 ff } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}