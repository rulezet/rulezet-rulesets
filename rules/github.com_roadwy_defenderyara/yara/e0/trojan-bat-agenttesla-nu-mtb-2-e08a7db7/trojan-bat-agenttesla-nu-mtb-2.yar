rule Trojan_BAT_AgentTesla_NU_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {07 02 09 18 6f [0-04] 1f ?? 28 [0-04] 28 [0-04] 6f [0-04] 26 09 18 d6 0d 09 08 31 } 		$a_02_1 = {91 08 61 07 11 ?? 91 61 b4 9c 11 [0-02] 6f [0-04] 17 da fe [0-09] 2c ?? 16 13 [0-02] 2b [0-02] 11 ?? 17 d6 13 [0-02] 11 ?? 17 d6 13 ?? 11 ?? 11 ?? 31 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1) >=2
 
}