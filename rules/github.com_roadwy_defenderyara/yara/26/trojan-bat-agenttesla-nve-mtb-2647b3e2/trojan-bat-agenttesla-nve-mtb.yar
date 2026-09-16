rule Trojan_BAT_AgentTesla_NVE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NVE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {57 1d a2 0b 09 1f 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 68 00 00 00 12 00 00 00 d2 02 00 00 8c 05 00 00 ce 02 00 00 b5 00 00 00 01 00 00 00 b5 } 		$a_01_1 = {50 75 72 76 69 6c 65 2e 52 65 73 6f 75 72 63 65 73 2e 72 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=2
 
}