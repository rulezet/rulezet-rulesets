rule Trojan_Win32_Qakbot_EB_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.EB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b d8 8b 45 d8 8b 00 03 45 a8 03 d8 } 		$a_01_1 = {03 d8 8b 45 d8 33 18 89 5d a0 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}