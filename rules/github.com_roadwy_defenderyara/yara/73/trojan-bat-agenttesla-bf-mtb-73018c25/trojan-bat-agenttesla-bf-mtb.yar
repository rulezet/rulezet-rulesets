rule Trojan_BAT_AgentTesla_BF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {06 17 58 20 ff 00 00 00 5f 0a 07 05 06 95 58 20 ff 00 00 00 5f 0b 02 05 06 8f ?? 00 00 01 05 07 8f ?? 00 00 01 28 ?? 00 00 06 00 05 06 95 05 07 95 58 20 ff 00 00 00 5f 0d 04 08 03 08 91 05 09 95 61 d2 9c 00 08 17 58 0c 08 03 8e 69 fe 04 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}