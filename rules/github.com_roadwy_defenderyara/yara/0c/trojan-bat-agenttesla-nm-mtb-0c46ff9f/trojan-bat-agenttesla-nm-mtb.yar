rule Trojan_BAT_AgentTesla_NM_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NM!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 d5 a2 ff 09 1f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 68 00 00 00 1e 00 00 00 5e 00 00 00 7f 01 00 00 4c 00 00 00 ae 00 00 00 ce 00 00 00 01 00 00 00 01 00 00 00 2c 00 00 00 0a 00 00 00 25 } 		$a_01_1 = {50 69 7a 7a 61 5f 41 70 70 5f 55 73 65 72 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}