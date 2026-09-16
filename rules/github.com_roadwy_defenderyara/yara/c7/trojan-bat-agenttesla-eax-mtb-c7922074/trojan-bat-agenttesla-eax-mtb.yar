rule Trojan_BAT_AgentTesla_EAX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.EAX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {e0 02 e7 02 eb 02 e7 02 e2 02 df 02 df 02 df 02 05 03 0b 03 df 02 eb 02 df 02 df 02 e1 02 05 03 e6 02 df 02 df 02 df 02 10 03 e5 02 f7 02 ce 02 e7 02 df 02 df 02 df 02 } 		$a_01_1 = {42 00 75 00 6e 00 69 00 66 00 75 00 5f 00 54 00 65 00 78 00 74 00 42 00 6f 00 78 00 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}