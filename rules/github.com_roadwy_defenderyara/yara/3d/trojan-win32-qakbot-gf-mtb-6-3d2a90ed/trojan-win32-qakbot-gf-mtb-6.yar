rule Trojan_Win32_Qakbot_GF_MTB_6{
	meta:
		description = "Trojan:Win32/Qakbot.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {8a ca 81 c6 88 3c 03 01 8b 54 24 [0-01] 2a ca 80 c1 [0-01] 89 35 [0-04] 89 b4 2b [0-04] 83 c5 04 8b 1d [0-04] 0f b6 c1 66 2b c3 89 6c 24 [0-01] 66 03 f8 66 89 7c 24 [0-01] 81 fd 4e 0a 00 00 73 [0-01] 8b 6c 24 [0-01] e9 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}