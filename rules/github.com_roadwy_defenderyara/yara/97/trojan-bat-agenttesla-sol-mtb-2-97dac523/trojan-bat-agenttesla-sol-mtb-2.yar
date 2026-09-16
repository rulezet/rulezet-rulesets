rule Trojan_BAT_AgentTesla_SOL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SOL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {11 14 11 16 61 13 17 11 07 11 13 d4 11 17 20 ff 00 00 00 5f d2 9c 16 13 1b 2b 25 00 11 17 6e 11 1b 6a 5a 11 16 6e 58 69 20 00 01 00 00 5d 13 1c 11 1c 19 58 1f 40 5d 13 1c 00 11 1b 17 58 13 1b 11 1b 19 fe 04 13 1d 11 1d 2d d0 } 		$a_81_1 = {46 37 48 38 41 38 37 35 35 34 42 38 38 38 51 4a 48 35 37 34 45 32 } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}