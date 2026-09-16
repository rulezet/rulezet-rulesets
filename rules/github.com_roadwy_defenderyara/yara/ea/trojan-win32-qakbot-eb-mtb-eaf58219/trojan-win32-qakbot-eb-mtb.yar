rule Trojan_Win32_Qakbot_EB_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 13 2b 17 8b 45 f8 8a 14 10 8b 45 08 32 14 08 8b 45 fc 88 14 08 } 	condition:
		((#a_01_0  & 1)*5) >=5
 
}