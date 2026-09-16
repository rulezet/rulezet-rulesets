rule Trojan_BAT_AgentTesla_MBDH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBDH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 33 65 61 39 35 63 62 37 2d 30 64 66 34 2d 34 65 62 36 2d 61 66 31 64 2d 38 34 63 33 65 64 33 39 38 31 34 65 } 		$a_01_1 = {50 75 7a 7a 6c 65 47 61 6d 65 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}