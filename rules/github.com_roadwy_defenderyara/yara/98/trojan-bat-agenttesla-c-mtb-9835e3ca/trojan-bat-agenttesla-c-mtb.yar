rule Trojan_BAT_AgentTesla_C_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.C!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {06 11 0d 11 0e 58 0e 04 58 20 ff 00 00 00 5f 91 13 0f } 		$a_01_1 = {0e 04 06 1f 11 91 18 62 61 10 04 11 19 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*3) >=5
 
}