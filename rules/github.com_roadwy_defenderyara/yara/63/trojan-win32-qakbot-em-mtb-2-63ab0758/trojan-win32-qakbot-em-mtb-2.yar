rule Trojan_Win32_Qakbot_EM_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.EM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b cb 83 c6 04 0b cf 0b 4c 24 30 0b d1 8b cd 89 90 a8 00 00 00 2b 48 0c 69 c9 4c 03 00 00 3b f1 72 de } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}