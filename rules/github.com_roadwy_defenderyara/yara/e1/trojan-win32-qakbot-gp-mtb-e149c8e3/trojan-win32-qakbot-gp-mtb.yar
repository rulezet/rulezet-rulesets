rule Trojan_Win32_Qakbot_GP_MTB{
	meta:
		description = "Trojan:Win32/Qakbot.GP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {2b d8 4b 8b 45 d8 33 18 89 5d a0 [0-32] 03 d8 8b 45 d8 89 18 8b 45 a8 83 c0 04 89 45 a8 33 c0 89 45 a4 8b 45 d8 83 c0 04 03 45 a4 89 45 d8 8b 45 a8 3b 45 cc 0f 82 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}