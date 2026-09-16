rule Trojan_BAT_AgentTesla_SIO_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SIO!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 19 5d 16 fe 01 0c 08 2c 08 02 07 02 07 91 03 61 9c 07 17 d6 0b 07 06 31 e6 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}