rule Trojan_Win32_Qakbot_EB_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 55 d8 33 02 89 45 a0 8b 45 a0 8b 55 d8 89 02 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}