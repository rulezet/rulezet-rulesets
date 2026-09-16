rule Trojan_BAT_AgentTesla_AMBC_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBC!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {91 61 07 11 ?? 20 ?? ?? ?? ?? 5d 91 20 00 01 00 00 58 20 00 01 00 00 5d 59 d2 9c } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}