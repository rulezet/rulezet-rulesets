rule Trojan_BAT_AgentTesla_RP_MTB_15{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {fe 09 01 00 20 1f 00 00 00 8f 0c 00 00 01 25 47 20 7f 00 00 00 5f d2 52 fe 09 01 00 20 1f 00 00 00 8f 0c 00 00 01 25 47 20 40 00 00 00 60 d2 52 fe 09 01 00 20 00 00 00 00 8f 0c 00 00 01 25 47 20 f8 00 00 00 5f d2 52 2a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}