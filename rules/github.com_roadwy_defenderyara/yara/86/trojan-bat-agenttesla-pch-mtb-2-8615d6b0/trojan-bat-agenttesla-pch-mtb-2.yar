rule Trojan_BAT_AgentTesla_PCH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.PCH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 01 00 00 "
		
	strings :
		$a_03_0 = {00 02 7b 34 00 00 04 7b 29 00 00 04 02 7b 38 00 00 04 8f 1f 00 00 01 25 47 02 7b 35 00 00 04 02 7b 38 00 00 04 02 7b 35 00 00 04 6f ?? 00 00 0a 5d 6f ?? 00 00 0a 86 61 b4 52 00 02 7b 38 00 00 04 13 07 02 11 07 17 d6 7d 38 00 00 04 02 7b 38 00 00 04 02 7b 34 00 00 04 7b 29 00 00 04 8e 69 fe 04 13 08 11 08 2d 98 } 	condition:
		((#a_03_0  & 1)*4) >=4
 
}