rule Trojan_BAT_AgentTesla_MB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_02_0 = {a2 25 17 7e ?? ?? 00 04 a2 25 18 72 ?? ?? 00 70 a2 28 ?? ?? 00 0a 26 } 		$a_80_1 = {4d 61 69 6e 57 69 6e 64 6f 77 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_02_0  & 1)*1+(#a_80_1  & 1)*1) >=2
 
}