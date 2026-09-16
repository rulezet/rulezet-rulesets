rule Trojan_Win32_Qakbot_GF_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {0f b6 c9 f7 d9 2b c8 03 d9 8b 0d [0-04] 89 1d [0-04] 8b 84 11 [0-04] 05 0c f5 04 01 a3 [0-04] 89 84 11 [0-04] 83 c2 04 8b 35 [0-04] 8b 1d [0-04] 81 fa 83 11 00 00 73 ?? 8a 0d [0-04] eb } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}