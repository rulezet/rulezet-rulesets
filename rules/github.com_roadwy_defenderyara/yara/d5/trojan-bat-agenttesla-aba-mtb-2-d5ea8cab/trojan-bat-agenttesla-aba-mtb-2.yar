rule Trojan_BAT_AgentTesla_ABA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 19 20 a8 5c 08 bd 5a 20 ?? d0 59 94 61 38 ?? fd ff ff 12 05 28 ?? 00 00 0a 1b 5a 12 05 28 ?? 00 00 0a 1d 5a 61 12 05 28 69 ?? 00 0a 1f 0b 5a 61 06 7b ?? 00 00 04 61 13 10 11 10 20 ?? 00 00 00 5f 20 ?? 00 00 00 fe 01 13 11 11 19 20 ?? 6a 23 d6 5a 20 ?? b2 7e 80 61 } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}