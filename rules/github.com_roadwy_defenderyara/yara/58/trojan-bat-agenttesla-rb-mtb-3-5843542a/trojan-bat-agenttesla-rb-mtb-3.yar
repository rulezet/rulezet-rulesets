rule Trojan_BAT_AgentTesla_RB_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {03 08 03 8e 69 5d 03 08 03 8e 69 5d 91 07 08 07 8e 69 5d 91 61 28 ?? 00 00 0a 03 08 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}