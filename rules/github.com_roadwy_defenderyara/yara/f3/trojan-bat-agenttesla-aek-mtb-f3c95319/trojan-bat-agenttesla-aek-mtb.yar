rule Trojan_BAT_AgentTesla_AEK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AEK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 2c 72 01 00 00 70 2b 28 2b 2d 0d 16 2d 0e 09 08 6f 12 00 00 0a 08 6f 13 00 00 0a 0a de 0a } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}