rule Trojan_BAT_AgentTesla_CAH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.CAH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {05 03 05 8e 69 5d 91 04 03 1f 16 5d 91 61 28 ?? 00 00 06 05 03 17 58 05 8e 69 5d 91 28 ?? 00 00 06 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 0a } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}