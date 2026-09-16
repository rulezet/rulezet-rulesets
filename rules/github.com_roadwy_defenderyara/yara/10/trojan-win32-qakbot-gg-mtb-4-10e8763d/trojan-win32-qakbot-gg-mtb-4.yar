rule Trojan_Win32_Qakbot_GG_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {bb f1 32 01 00 bb f1 32 01 00 bb f1 32 01 00 bb f1 32 01 00 bb f1 32 01 00 bb f1 32 01 00 bb f1 32 01 00 bb f1 32 01 00 bb f1 32 01 00 bb f1 32 01 00 33 05 [0-04] 8b c8 8b d1 89 15 [0-04] a1 [0-04] 8b 0d [0-04] 89 08 5f 5b 5d c3 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}