rule Trojan_Win32_Emotet_GKM_MTB_6{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b ce 99 f7 f9 8b 45 ?? 83 c4 18 8a 8c 15 ?? ?? ?? ?? 30 08 40 ff 4d ?? 89 45 ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}