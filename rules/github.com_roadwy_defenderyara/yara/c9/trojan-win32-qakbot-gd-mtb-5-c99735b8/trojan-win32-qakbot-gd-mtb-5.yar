rule Trojan_Win32_Qakbot_GD_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {03 d8 8b 45 d8 33 18 89 5d a0 8b 45 a0 03 45 9c 2b 45 9c 8b 55 d8 89 02 } 		$a_01_1 = {03 d8 89 5d d8 8b 45 9c 2b 45 9c 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 a8 3b 45 cc 0f 82 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}