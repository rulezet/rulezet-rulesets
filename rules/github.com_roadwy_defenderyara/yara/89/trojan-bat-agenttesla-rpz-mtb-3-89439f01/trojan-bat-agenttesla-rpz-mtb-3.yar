rule Trojan_BAT_AgentTesla_RPZ_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 1f 19 fe 04 16 fe 01 0b 07 2c 17 02 7b 09 00 00 04 7b 1e 00 00 04 06 8f 04 00 00 02 17 7d 12 00 00 04 06 17 58 0a 06 1f 1e fe 04 0c 08 3a 26 ff ff ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}