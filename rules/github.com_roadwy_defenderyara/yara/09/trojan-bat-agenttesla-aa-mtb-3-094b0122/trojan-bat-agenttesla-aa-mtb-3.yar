rule Trojan_BAT_AgentTesla_AA_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 02 00 00 "
		
	strings :
		$a_01_0 = {0c 07 08 28 15 00 00 0a 2c 28 07 08 17 28 16 00 00 0a 7e 17 00 00 0a 72 1b 00 00 70 6f 18 00 00 0a 08 28 } 		$a_01_1 = {47 65 74 45 78 65 63 75 74 69 6e 67 41 73 73 65 6d 62 6c 79 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*1) >=3
 
}