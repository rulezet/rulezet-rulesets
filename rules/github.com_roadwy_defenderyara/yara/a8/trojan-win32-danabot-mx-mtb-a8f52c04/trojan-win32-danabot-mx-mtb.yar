rule Trojan_Win32_Danabot_MX_MTB{
	meta:
		description = "Trojan:Win32/Danabot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {33 ca c1 e8 05 03 c5 89 4c 24 ?? 89 44 24 ?? 8b 44 24 ?? 31 44 24 ?? 2b 7c 24 ?? 81 3d ?? ?? ?? ?? bb 06 00 00 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}