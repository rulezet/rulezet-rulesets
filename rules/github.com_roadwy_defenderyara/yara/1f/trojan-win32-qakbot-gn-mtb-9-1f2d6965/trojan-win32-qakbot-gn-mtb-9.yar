rule Trojan_Win32_Qakbot_GN_MTB_9{
	meta:
		description = "Trojan:Win32/Qakbot.GN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {fc f3 a4 83 bb [0-04] 00 75 } 		$a_02_1 = {50 5d 03 ab [0-04] 89 e8 5d ff 75 [0-02] 89 04 [0-02] 8d 83 [0-04] 51 29 0c [0-02] 01 04 [0-02] 8d 83 [0-04] ff 75 [0-02] 89 04 [0-02] ff 93 [0-04] 50 8f 45 [0-02] ff 75 [0-02] 8f 83 [0-04] 8f 45 [0-02] 8b 45 [0-02] ff e0 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}