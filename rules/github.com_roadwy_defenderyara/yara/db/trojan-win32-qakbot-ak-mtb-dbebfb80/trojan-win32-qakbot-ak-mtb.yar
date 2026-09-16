rule Trojan_Win32_Qakbot_AK_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.AK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,06 00 06 00 02 00 00 "
		
	strings :
		$a_01_0 = {8b 45 a8 03 45 ac 48 89 45 a4 8b 45 a8 8b 55 d8 01 02 } 		$a_01_1 = {8b 45 d8 33 18 89 5d a0 8b 45 a0 8b 55 d8 89 02 } 	condition:
		((#a_01_0  & 1)*3+(#a_01_1  & 1)*3) >=6
 
}