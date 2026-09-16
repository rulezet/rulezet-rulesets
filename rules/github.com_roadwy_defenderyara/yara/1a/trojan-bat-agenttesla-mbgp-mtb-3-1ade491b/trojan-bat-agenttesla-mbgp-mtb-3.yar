rule Trojan_BAT_AgentTesla_MBGP_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_03_0 = {11 07 11 06 11 21 9a 1f 10 28 ?? 00 00 0a b4 6f ?? 00 00 0a 00 11 21 17 d6 13 21 11 21 11 20 31 df } 		$a_01_1 = {4c 00 6f 00 2d 00 61 00 64 00 20 00 01 03 2d 00 01 13 51 00 75 00 61 00 6e 00 4c 00 79 00 42 00 61 00 6e 00 00 11 47 00 69 00 61 00 79 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}