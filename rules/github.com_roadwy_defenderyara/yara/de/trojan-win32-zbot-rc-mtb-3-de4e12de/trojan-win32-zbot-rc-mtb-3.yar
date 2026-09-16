rule Trojan_Win32_Zbot_RC_MTB_3{
	meta:
		description = "Trojan:Win32/Zbot.RC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {98 6c 00 8b c6 05 ?? 98 6c 00 ec c6 05 ?? 98 6c 00 83 c6 05 ?? 98 6c 00 c4 c6 05 ?? 98 6c 00 f0 c6 05 ?? 98 6c 00 b8 c6 05 ?? 98 6c 00 00 c6 05 ?? 98 6c 00 05 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}