rule Trojan_Win32_Emotet_GKM_MTB_9{
	meta:
		description = "Trojan:Win32/Emotet.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 cb 03 c1 99 8b ce f7 f9 8b 45 ?? 8a 4c 15 00 30 08 40 83 bd ?? ?? ?? ?? 00 89 45 ?? 0f 85 } 	condition:
		((#a_02_0  & 1)*2) >=2
 
}