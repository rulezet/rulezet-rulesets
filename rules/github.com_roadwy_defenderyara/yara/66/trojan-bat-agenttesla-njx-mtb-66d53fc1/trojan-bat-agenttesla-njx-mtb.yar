rule Trojan_BAT_AgentTesla_NJX_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NJX!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {7e 3d 00 00 04 18 9a 7e 3d 00 00 04 17 9a 20 de 07 00 00 95 e0 95 7e 3d 00 00 04 17 9a 20 71 0a 00 00 95 61 7e 3d 00 00 04 09 0d 17 9a 20 16 11 00 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}