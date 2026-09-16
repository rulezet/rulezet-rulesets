rule Trojan_Win32_Qakbot_GF_MTB_7{
	meta:
		description = "Trojan:Win32/Qakbot.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {81 c2 50 01 07 01 8b 44 24 [0-01] 2b c3 89 15 [0-04] 2b 05 [0-04] 66 a3 [0-04] 89 94 2e [0-04] 83 c5 04 a1 [0-04] 0f b7 3d [0-04] 83 c0 [0-01] 8b 15 [0-04] 03 d7 03 d0 89 54 24 [0-01] 89 15 [0-04] 81 fd 4b 26 00 00 73 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}