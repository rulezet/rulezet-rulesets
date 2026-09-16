rule Trojan_Win32_Qakbot_EC_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b c2 0f af c2 03 f0 89 b1 9c 00 00 00 8b 81 94 00 00 00 83 f0 2f 0b f8 42 89 79 24 3b 51 38 76 df } 	condition:
		((#a_01_0  & 1)*6) >=6
 
}