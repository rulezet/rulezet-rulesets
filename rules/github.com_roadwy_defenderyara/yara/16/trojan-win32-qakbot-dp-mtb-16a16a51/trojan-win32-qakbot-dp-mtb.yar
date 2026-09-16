rule Trojan_Win32_Qakbot_DP_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.DP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {8b 45 9c 8b 55 d8 01 02 8b 45 b4 83 e8 2c 03 45 9c 89 45 b0 8b 45 cc 03 45 b0 8b 55 d8 31 02 83 45 9c 04 8b 45 d8 83 c0 04 89 45 d8 8b 45 9c 99 52 50 8b 45 d4 33 d2 3b 54 24 04 75 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}