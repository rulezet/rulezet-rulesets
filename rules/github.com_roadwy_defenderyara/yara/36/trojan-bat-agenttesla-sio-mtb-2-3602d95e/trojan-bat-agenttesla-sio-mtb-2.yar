rule Trojan_BAT_AgentTesla_SIO_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SIO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {13 08 11 08 61 11 07 59 20 00 01 00 00 58 20 ff 00 00 00 5f 13 09 07 09 11 09 d2 9c 09 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}