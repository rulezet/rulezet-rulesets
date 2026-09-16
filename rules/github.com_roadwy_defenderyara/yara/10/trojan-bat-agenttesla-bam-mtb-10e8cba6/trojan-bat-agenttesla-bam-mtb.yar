rule Trojan_BAT_AgentTesla_BAM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 14 72 3a 3f 02 70 18 8d ?? 00 00 01 25 16 72 4a 3f 02 70 a2 25 17 72 4e 3f 02 70 a2 14 14 14 28 } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}