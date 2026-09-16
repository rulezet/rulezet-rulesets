rule Trojan_Win32_Qakbot_EC_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8a d1 8b cb 2a d3 80 c2 1b 01 1e 0f b6 c2 83 56 04 00 2b c8 81 e9 71 51 01 00 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}