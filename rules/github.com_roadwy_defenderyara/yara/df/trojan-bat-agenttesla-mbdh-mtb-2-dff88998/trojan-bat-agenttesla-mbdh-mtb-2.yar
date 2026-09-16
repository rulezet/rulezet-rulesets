rule Trojan_BAT_AgentTesla_MBDH_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {2b 19 00 07 06 08 8f ?? 00 00 01 28 ?? 00 00 0a 28 ?? 00 00 0a 0b 00 08 17 59 0c 08 15 fe 02 0d 09 2d df } 		$a_01_1 = {36 61 65 62 38 62 63 32 2d 33 65 32 36 2d 34 62 63 38 2d 62 36 30 39 2d 63 30 33 38 64 36 34 66 66 61 39 66 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}