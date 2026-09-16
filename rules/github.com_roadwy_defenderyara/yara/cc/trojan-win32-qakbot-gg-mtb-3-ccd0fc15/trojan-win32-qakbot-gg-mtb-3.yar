rule Trojan_Win32_Qakbot_GG_MTB_3{
	meta:
		description = "Trojan:Win32/Qakbot.GG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {89 c1 8b 45 [0-02] fc f3 a4 57 c7 04 [0-06] 59 55 33 2c [0-02] 0b ab [0-04] 83 e0 00 31 e8 5d 56 81 04 [0-06] 29 34 [0-02] 8f 83 [0-04] 21 8b [0-04] 6a 00 31 2c [0-02] 50 5d 03 ab [0-04] 89 e8 5d ff e0 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}