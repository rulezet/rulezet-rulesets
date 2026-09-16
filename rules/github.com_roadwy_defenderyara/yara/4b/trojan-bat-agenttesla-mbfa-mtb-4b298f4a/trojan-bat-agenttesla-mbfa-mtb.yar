rule Trojan_BAT_AgentTesla_MBFA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {11 0b 08 11 08 1f 16 5d 91 61 07 11 0a 91 59 20 00 01 00 00 58 20 00 01 00 00 5d } 		$a_01_1 = {51 75 61 6e 6c 79 4e 68 61 68 61 6e 67 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}