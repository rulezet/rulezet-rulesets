rule Trojan_Win32_Qakbot_GQ_MTB_4{
	meta:
		description = "Trojan:Win32/Qakbot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 53 [0-02] a1 [0-04] a3 [0-04] 8b [0-05] 8b [0-02] 89 [0-05] 8b [0-05] a1 [0-04] a3 [0-04] b8 [0-04] b8 [0-04] a1 [0-04] 8b d8 33 d9 c7 05 [0-04] 00 00 00 00 01 [0-05] a1 [0-04] 8b 0d [0-04] 89 08 5b 5d c3 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}