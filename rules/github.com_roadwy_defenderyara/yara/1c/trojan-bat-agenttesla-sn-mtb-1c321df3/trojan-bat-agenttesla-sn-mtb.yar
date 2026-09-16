rule Trojan_BAT_AgentTesla_SN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 07 00 00 06 28 60 02 00 0a 6f 61 02 00 0a 13 04 73 62 02 00 0a 0b 28 55 07 00 06 75 3b 00 00 1b 73 63 02 00 0a 0c 08 11 04 16 73 64 02 00 0a } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}