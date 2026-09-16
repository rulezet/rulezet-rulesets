rule Trojan_Win32_AgentTesla_BA_MTB{
	meta:
		description = "Trojan:Win32/AgentTesla.BA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {b8 02 00 00 00 8b [0-02] 80 ?? ?? ?? 83 ?? ?? 3b ?? ?? ?? ?? ?? 7c } 		$a_02_1 = {0f 6f 06 0f [0-02] 83 [0-02] 83 [0-02] e2 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}