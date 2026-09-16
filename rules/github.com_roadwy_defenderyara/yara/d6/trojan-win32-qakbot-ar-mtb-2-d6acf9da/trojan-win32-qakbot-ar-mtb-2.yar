rule Trojan_Win32_Qakbot_AR_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.AR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8d 8c 10 fd 8a 67 00 89 4d f8 8b 55 f8 81 ea fd 8a 67 00 89 55 f8 b8 23 5f ff ff 03 05 ?? ?? ?? ?? 8b 80 19 a1 00 00 a3 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}