rule Trojan_BAT_AgentTesla_MBCG_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBCG!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {24 36 66 63 37 30 61 62 61 2d 31 32 66 31 2d 34 66 38 32 2d 39 32 32 36 2d 62 63 33 34 35 31 36 30 36 62 31 33 } 		$a_01_1 = {50 69 6e 74 65 72 65 73 74 5f 42 6f 61 72 64 5f 4d 61 6e 61 67 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}