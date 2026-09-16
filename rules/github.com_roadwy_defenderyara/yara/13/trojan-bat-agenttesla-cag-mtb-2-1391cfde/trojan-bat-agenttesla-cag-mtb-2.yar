rule Trojan_BAT_AgentTesla_CAG_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CAG!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 06 02 11 06 91 08 61 07 11 07 91 61 b4 9c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}