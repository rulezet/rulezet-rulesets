rule Trojan_BAT_AgentTesla_MBEI_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {07 8e 69 5d 13 08 11 04 08 6f ?? 00 00 0a 5d 13 09 07 11 08 91 13 0a 08 11 09 6f ?? 00 00 0a 13 0b 02 07 11 04 28 ?? 00 00 06 13 0c 02 11 0a 11 0b 11 0c } 		$a_01_1 = {45 00 37 00 51 00 43 00 59 00 37 00 34 00 43 00 46 00 38 00 38 00 34 00 41 00 5a 00 44 00 34 00 41 00 38 00 5a 00 39 00 53 00 35 00 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}