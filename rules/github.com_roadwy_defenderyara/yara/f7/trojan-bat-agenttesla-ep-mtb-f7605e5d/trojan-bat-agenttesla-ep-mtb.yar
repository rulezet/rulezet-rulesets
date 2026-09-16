rule Trojan_BAT_AgentTesla_EP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_02_0 = {07 11 05 02 11 05 91 06 61 09 08 91 61 b4 9c 08 03 6f ?? ?? ?? 0a 17 da 33 04 16 0c 2b 04 08 17 d6 0c 11 05 17 d6 13 05 } 		$a_81_1 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_81_2 = {41 63 74 69 76 61 74 6f 72 } 	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1) >=12
 
}