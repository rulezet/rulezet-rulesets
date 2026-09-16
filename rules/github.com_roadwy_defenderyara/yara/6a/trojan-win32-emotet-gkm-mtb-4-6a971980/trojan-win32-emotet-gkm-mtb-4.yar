rule Trojan_Win32_Emotet_GKM_MTB_4{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {03 c1 99 b9 6b 1c 00 00 f7 f9 45 8a 54 14 ?? 30 55 ?? 83 bc 24 ?? ?? ?? ?? ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}