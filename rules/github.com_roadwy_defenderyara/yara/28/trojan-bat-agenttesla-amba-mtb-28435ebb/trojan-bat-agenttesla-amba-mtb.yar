rule Trojan_BAT_AgentTesla_AMBA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMBA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 02 07 6f ?? 00 00 0a 08 59 09 59 20 00 01 00 00 5d 13 } 		$a_03_1 = {8e 69 5d 91 61 d2 52 00 11 ?? 17 58 13 } 	condition:
		((#a_03_0  & 1)*1+(#a_03_1  & 1)*1) >=2
 
}