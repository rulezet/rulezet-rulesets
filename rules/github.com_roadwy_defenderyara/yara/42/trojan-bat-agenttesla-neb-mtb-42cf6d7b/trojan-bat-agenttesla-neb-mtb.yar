rule Trojan_BAT_AgentTesla_NEB_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NEB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {11 00 03 05 1f 16 5d 6f 65 00 00 0a 61 13 01 38 00 00 00 00 38 12 00 00 00 38 0d 00 00 00 00 02 05 04 5d 91 13 00 38 d5 ff ff ff } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}