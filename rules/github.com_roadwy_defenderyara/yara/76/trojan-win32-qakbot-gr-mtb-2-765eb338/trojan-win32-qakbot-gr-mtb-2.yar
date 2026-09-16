rule Trojan_Win32_Qakbot_GR_MTB_2{
	meta:
		description = "Trojan:Win32/Qakbot.GR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 57 c7 04 e4 ff ff [0-02] 59 56 83 e6 00 0b b3 [0-04] 83 e0 00 09 f0 5e 68 [0-04] 8f 83 [0-04] 21 8b [0-04] 6a 00 01 [0-02] 50 5a 03 93 [0-04] 89 d0 5a ff e0 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}