rule Trojan_BAT_AgentTesla_EAV_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAV!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {0b 16 0c 2b 1f 00 07 08 02 08 91 6e 08 06 5d 28 ?? 00 00 06 6a 59 20 ff 00 00 00 6a 5f d2 9c 00 08 17 58 0c 08 02 8e 69 fe 04 13 04 11 04 2d d5 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}