rule Trojan_BAT_AgentTesla_MBCN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 06 08 11 06 91 07 11 06 07 8e 69 5d 91 61 d2 9c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}