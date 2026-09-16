rule Trojan_Win32_Qakbot_GE_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 8b d2 31 0d [0-04] c7 05 [0-04] 00 00 00 00 8b 1d [0-04] 01 1d [0-04] a1 [0-04] 8b 0d [0-04] 89 08 5b 5d c3 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}