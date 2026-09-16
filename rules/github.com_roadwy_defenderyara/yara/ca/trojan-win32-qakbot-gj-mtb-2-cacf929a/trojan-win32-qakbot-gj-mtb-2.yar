rule Trojan_Win32_Qakbot_GJ_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GJ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 e8 8b 55 ec 01 02 8b 45 d8 03 45 b0 03 45 e8 89 45 b4 6a 00 e8 } 		$a_01_1 = {2b d8 8b 45 ec 31 18 83 45 e8 04 83 45 ec 04 8b 45 e8 3b 45 e4 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}