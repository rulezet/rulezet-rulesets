rule Trojan_BAT_AgentTesla_SIK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {07 11 04 11 05 6f 3e 00 00 0a 13 06 08 12 06 28 ?? ?? ?? ?? 6f 40 00 00 0a 08 6f 41 00 00 0a 20 00 40 01 00 2f 0d 08 12 06 28 ?? ?? ?? ?? 6f 40 00 00 0a 08 6f 41 00 00 0a 20 00 40 01 00 2f 0d 08 12 06 28 ?? ?? ?? ?? 6f 40 00 00 0a 11 05 17 58 13 05 11 05 07 6f 44 00 00 0a 32 a3 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}