rule Trojan_Win32_Qakbot_PAE_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.PAE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 02 00 00 "
		
	strings :
		$a_01_0 = {33 d2 8b c3 f7 75 f4 8b 45 08 8a 04 02 32 04 3b 88 04 19 43 83 ee 01 } 		$a_01_1 = {8b 55 fc 32 04 13 0f b6 c0 66 89 04 4e 41 43 3b cf } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=10
 
}