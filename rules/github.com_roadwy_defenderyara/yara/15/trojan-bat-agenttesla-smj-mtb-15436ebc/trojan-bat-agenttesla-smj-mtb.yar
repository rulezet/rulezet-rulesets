rule Trojan_BAT_AgentTesla_SMJ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SMJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {09 11 05 91 11 04 11 05 91 3b 02 00 00 00 16 2a 11 05 17 58 13 05 11 05 09 8e 69 32 e3 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}