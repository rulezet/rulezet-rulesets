rule Trojan_Win32_Qakbot_ED_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.ED!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {03 d8 43 8b 45 d8 89 18 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 } 	condition:
		((#a_01_0  & 1)*8) >=8
 
}