rule Trojan_BAT_AgentTesla_SKF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SKF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_00_0 = {08 11 04 07 11 04 91 09 11 04 09 6f 37 00 00 0a 5d 6f 38 00 00 0a 61 d2 9c 11 04 17 58 13 04 11 04 07 8e 69 32 da } 		$a_81_1 = {68 74 74 70 73 3a 2f 2f 69 6e 73 70 69 72 65 63 6f 6c 6c 65 67 65 2e 63 6f 2e 75 6b 2f 74 72 61 73 68 73 73 2f } 	condition:
		((#a_00_0  & 1)*1+(#a_81_1  & 1)*1) >=2
 
}