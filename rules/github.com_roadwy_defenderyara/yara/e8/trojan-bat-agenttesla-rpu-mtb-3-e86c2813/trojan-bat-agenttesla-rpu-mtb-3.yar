rule Trojan_BAT_AgentTesla_RPU_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.RPU!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {2b 1b 0a 2b db 7d 01 00 00 04 2b e7 0b 2b f1 20 d0 07 00 00 38 aa 00 00 00 07 17 58 0b 07 1b fe 04 0c 08 2c 03 17 2b 03 16 2b 00 2d e2 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}