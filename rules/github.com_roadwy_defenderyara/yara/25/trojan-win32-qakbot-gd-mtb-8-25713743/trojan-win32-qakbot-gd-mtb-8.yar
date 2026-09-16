rule Trojan_Win32_Qakbot_GD_MTB_8{
	meta:
		description = "Trojan:Win32/Qakbot.GD!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 ce 8a f2 2b ce 2a f3 8b 74 24 [0-01] 81 c1 [0-04] 89 4c 24 [0-01] 80 c6 [0-01] 8a 54 24 [0-01] 89 0d [0-04] 80 c2 [0-01] 8b 0e 02 d3 81 c1 [0-04] 88 35 [0-04] 89 0e 83 c6 04 83 6c 24 [0-01] 01 89 74 24 [0-01] 8b 74 24 [0-01] 89 0d [0-04] 0f 85 } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}