rule Trojan_Win32_TrickBot_GQ_MTB{
	meta:
		description = "Trojan:Win32/TrickBot.GQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {61 00 66 c7 [0-02] 73 00 66 c7 [0-02] 77 00 66 c7 [0-02] 68 00 66 c7 [0-02] 6f 00 66 c7 [0-02] 6f 00 66 c7 [0-02] 6b 00 66 c7 [0-02] 2e 00 66 c7 [0-02] 64 00 66 c7 [0-02] 6c 00 66 c7 [0-02] 6c 00 } 		$a_02_1 = {33 d2 5b 8d 0c [0-02] 8b [0-02] f7 [0-02] 8b 44 [0-02] 8a [0-02] 30 01 46 3b 74 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}