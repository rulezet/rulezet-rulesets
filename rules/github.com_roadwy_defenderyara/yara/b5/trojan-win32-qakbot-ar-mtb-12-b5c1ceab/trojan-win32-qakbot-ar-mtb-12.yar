rule Trojan_Win32_Qakbot_AR_MTB_12{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {8d 8c 06 c2 5a 00 00 8b 55 08 89 0a } 		$a_01_1 = {8b 45 08 8b 08 2b ce 8b 55 08 89 0a } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}