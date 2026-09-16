rule Trojan_BAT_AgentTesla_MTQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MTQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_02_0 = {69 6a 5d d4 91 06 07 06 8e 69 6a 5d d4 91 61 28 ?? ?? 00 0a 02 07 17 6a 58 02 8e 69 6a 5d d4 91 28 ?? ?? 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5e } 	condition:
		((#a_02_0  & 1)*10) >=10
 
}