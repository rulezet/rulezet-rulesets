rule Trojan_Win32_Qakbot_EA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 6c 24 4c 8b 97 c8 00 00 00 8b 87 14 01 00 00 8b 8f 0c 01 00 00 8b 04 82 31 04 8a 8b 8f 38 01 00 00 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}