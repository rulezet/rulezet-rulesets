rule Trojan_Win32_Qakbot_EB_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_03_0 = {8b d3 03 f8 8b 86 48 01 00 00 8b cf d3 ea 8b 4e 1c 8a 40 ?? 34 ?? 22 d0 8b 86 34 01 00 00 88 14 01 } 	condition:
		((#a_03_0  & 1)*6) >=6
 
}