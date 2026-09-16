rule Trojan_BAT_AgentTesla_RP_MTB_9{
	meta:
		description = "Trojan:BAT/AgentTesla.RP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {08 17 58 09 5d 13 06 07 08 07 08 91 11 04 08 1f 16 5d 91 61 07 11 06 91 59 20 00 01 00 00 58 20 ff 00 00 00 5f 28 b4 00 00 0a 9c 08 17 58 0c 08 09 32 cd } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}