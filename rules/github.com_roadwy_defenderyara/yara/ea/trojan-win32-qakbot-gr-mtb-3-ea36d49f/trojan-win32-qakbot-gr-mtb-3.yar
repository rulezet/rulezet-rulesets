rule Trojan_Win32_Qakbot_GR_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {51 68 00 10 00 00 52 50 ff 93 [0-06] 89 bb [0-04] 8b b3 [0-04] 8b 8b [0-04] fc f3 a4 b9 ff ff 0f 00 8b 83 [0-04] 68 [0-04] 8f 83 [0-04] 21 8b [0-04] 03 83 [0-04] ff e0 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}