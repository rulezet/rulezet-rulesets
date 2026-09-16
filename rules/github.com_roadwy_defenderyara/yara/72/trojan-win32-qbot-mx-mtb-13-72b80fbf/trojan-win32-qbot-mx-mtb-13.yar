rule Trojan_Win32_Qbot_MX_MTB_13{
	meta:
		description = "Trojan:Win32/Qbot.MX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_02_0 = {5b d3 c0 8a fc 8a e6 d3 cb ff 4d fc 75 ?? 81 [0-05] 33 [0-02] 83 [0-02] 6a 00 89 [0-02] 29 d2 31 da 89 d0 5a aa 49 75 } 		$a_02_1 = {89 fa 5f 6a ?? 8f ?? ?? d3 c0 8a fc 8a e6 d3 cb ff ?? ?? 75 ?? 8f ?? ?? 8b ?? ?? 56 83 ?? ?? 31 ?? 83 ?? ?? 31 ?? 5e aa 49 75 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=1
 
}