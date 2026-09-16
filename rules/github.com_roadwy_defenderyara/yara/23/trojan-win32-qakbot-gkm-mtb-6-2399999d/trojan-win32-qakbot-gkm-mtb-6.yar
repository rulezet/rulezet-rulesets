rule Trojan_Win32_Qakbot_GKM_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GKM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {68 cf 0d 00 00 6a 00 e8 ?? ?? ?? ?? 03 d8 01 5d ?? 8b 45 ?? 01 45 ?? 8b 45 ?? 01 45 ?? eb } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}