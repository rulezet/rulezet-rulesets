rule Trojan_Win32_Qakbot_EH_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.EH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 97 fc 00 00 00 8b 87 44 01 00 00 8b 8f 3c 01 00 00 8b 04 82 31 04 8a } 		$a_01_1 = {8b 8f 44 01 00 00 8b 87 fc 00 00 00 8b b7 3c 01 00 00 8b 97 f8 00 00 00 8b 04 88 01 04 b2 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}