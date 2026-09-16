rule Trojan_BAT_AgentTesla_AMBA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 1b 09 5d 13 1c 11 1b 11 04 5d 13 1d 07 11 1c 91 13 1e 08 11 1d 6f ?? 00 00 0a 13 1f 02 07 11 1b 28 ?? 00 00 06 13 20 02 11 1e 11 1f 11 20 28 ?? 00 00 06 13 21 07 11 1c 11 21 20 00 01 00 00 5d d2 9c 00 11 1b 17 59 13 1b 11 1b 16 fe 04 16 fe 01 13 22 11 22 2d a7 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}