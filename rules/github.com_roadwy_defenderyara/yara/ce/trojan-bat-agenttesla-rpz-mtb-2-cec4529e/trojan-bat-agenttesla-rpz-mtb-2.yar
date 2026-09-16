rule Trojan_BAT_AgentTesla_RPZ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.RPZ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {0a 06 18 5b 8d 6d 00 00 01 0b 16 0c 2b 1a 00 07 08 18 5b 02 08 18 6f a2 00 00 0a 1f 10 28 a3 00 00 0a 9c 00 08 18 58 0c 08 06 fe 04 0d 09 2d } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}