rule Trojan_Win32_Danabot_KM_MTB_2{
	meta:
		description = "Trojan:Win32/Danabot.KM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {d3 e2 89 74 24 ?? 89 54 24 ?? 8b 44 24 ?? 01 44 24 ?? 8b 44 24 ?? 01 44 24 ?? a1 ?? ?? ?? ?? 3d 1a 0c 00 00 75 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}