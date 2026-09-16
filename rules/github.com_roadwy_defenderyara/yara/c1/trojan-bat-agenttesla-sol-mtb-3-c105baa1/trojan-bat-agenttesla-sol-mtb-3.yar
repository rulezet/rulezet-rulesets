rule Trojan_BAT_AgentTesla_SOL_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.SOL!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {28 b4 00 00 0a 72 0f 0c 00 70 6f b5 00 00 0a 09 1f 16 5d 91 13 04 07 09 91 11 04 61 13 05 09 17 58 08 5d 13 06 07 11 06 91 13 07 20 00 01 00 00 13 08 11 05 11 07 59 11 08 58 11 08 17 59 5f 13 09 07 09 11 09 d2 9c 09 17 58 0d 09 08 32 b1 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}