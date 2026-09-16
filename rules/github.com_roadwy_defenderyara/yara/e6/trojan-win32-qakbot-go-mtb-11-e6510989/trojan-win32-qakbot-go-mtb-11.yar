rule Trojan_Win32_Qakbot_GO_MTB_11{
	meta:
		description = "Trojan:Win32/Qakbot.GO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {55 8b ec 83 c4 [0-02] 57 8b 4d [0-02] 8b f9 03 f9 33 7d [0-02] 3b f9 76 [0-02] 51 51 57 ff 75 [0-02] e8 [0-04] 59 49 75 [0-02] b8 00 00 00 00 5f c9 c2 } 		$a_02_1 = {51 68 00 10 00 00 52 50 ff 93 [0-04] 8b f8 89 bb [0-04] 8b b3 [0-04] 8b 8b [0-04] fc f3 a4 b9 [0-04] 8b 83 [0-04] 68 [0-04] 8f 83 [0-04] 21 8b [0-04] 03 83 [0-04] ff e0 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}