rule Trojan_Win32_Danabot_MBFW_MTB_2{
	meta:
		description = "Trojan:Win32/Danabot.MBFW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 45 d0 89 45 ec 8b 45 f8 89 45 f0 8b 45 e8 01 45 fc 8b 45 fc 31 45 f0 } 		$a_03_1 = {8b 45 f8 8b 55 f4 33 45 ec 81 c3 ?? ?? ?? ?? 8b 4d dc 2b f0 89 45 f8 89 75 fc 4f } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}