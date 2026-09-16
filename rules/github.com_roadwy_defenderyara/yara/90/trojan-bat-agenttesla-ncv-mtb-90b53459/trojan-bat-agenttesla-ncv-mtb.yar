rule Trojan_BAT_AgentTesla_NCV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 09 02 09 91 07 09 07 8e 69 5d 91 61 d2 9c 08 09 91 2d 0b 08 09 09 20 ff 00 00 00 5d d2 9c 09 17 58 0d 09 1f 20 32 d8 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}