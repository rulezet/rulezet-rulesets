rule Trojan_Win32_Qakbot_EK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.EK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 55 a8 03 55 ac 4a 2b d0 89 55 a4 } 		$a_01_1 = {8b 55 d8 8b 12 03 55 a8 2b d0 8b 45 d8 89 10 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*2) >=5
 
}