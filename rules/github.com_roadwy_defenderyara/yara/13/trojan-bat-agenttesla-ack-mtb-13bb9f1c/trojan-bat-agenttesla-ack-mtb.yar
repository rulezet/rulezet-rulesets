rule Trojan_BAT_AgentTesla_ACK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ACK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {00 19 8d 5e 00 00 01 25 16 12 02 28 59 00 00 0a 9c 25 17 12 02 28 5a 00 00 0a 9c 25 18 12 02 28 5b 00 00 0a 9c 13 06 19 } 		$a_81_1 = {43 72 75 64 41 70 70 6c 69 63 61 74 69 6f 6e 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*2+(#a_81_1  & 1)*2) >=4
 
}