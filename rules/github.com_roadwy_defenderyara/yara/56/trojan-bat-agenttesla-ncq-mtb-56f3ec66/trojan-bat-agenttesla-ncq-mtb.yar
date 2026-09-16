rule Trojan_BAT_AgentTesla_NCQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 08 07 6f 0a 00 00 0a 00 00 de 0b 08 2c 07 08 ?? ?? ?? ?? ?? 00 dc 07 ?? ?? ?? ?? ?? 0d 2b 00 09 2a } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}