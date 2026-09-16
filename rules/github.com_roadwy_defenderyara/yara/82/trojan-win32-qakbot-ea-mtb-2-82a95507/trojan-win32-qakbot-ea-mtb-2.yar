rule Trojan_Win32_Qakbot_EA_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.EA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {33 10 89 55 a0 8b 45 a0 8b 55 d8 89 02 33 c0 89 45 a4 8b 45 a8 83 c0 04 03 45 a4 89 45 a8 8b 45 d8 83 c0 04 03 45 a4 } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}