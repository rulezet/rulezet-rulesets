rule Trojan_Win32_Qakbot_GA_MTB_5{
	meta:
		description = "Trojan:Win32/Qakbot.GA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b9 40 00 00 00 [0-04] 00 ff 75 [0-04] 68 00 10 00 00 [0-06] 00 ff 75 [0-04] 57 83 [0-02] 00 31 [0-02] ff 93 } 		$a_02_1 = {fc f3 a4 b9 ff ff [0-02] ff b3 [0-04] 8f 45 [0-02] ff 75 [0-02] 58 68 [0-04] 8f 83 [0-04] 21 8b [0-04] 57 8b bb [0-04] 50 8f 45 [0-02] 01 7d [0-02] ff 75 [0-02] 58 5f ff e0 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}