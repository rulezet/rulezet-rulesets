rule Trojan_Win32_Qakbot_EC_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,08 00 08 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 82 9c 00 00 00 33 c5 33 42 30 0f af 82 d4 00 00 00 89 82 d4 00 00 00 8b 82 a8 00 00 00 83 c1 02 23 42 48 } 	condition:
		((#a_01_0  & 1)*8) >=8
 
}