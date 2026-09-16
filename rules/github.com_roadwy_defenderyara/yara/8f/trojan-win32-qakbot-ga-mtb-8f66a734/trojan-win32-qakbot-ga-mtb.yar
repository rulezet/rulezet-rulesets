rule Trojan_Win32_Qakbot_GA_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {89 02 8b 45 c4 03 45 a4 03 45 9c 2b 45 9c 89 45 a0 8b 45 a0 03 45 9c 2b 45 9c 8b 55 d8 33 02 89 45 a0 8b 45 a0 03 45 9c 2b 45 9c 8b 55 d8 89 02 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}