rule Trojan_BAT_AgentTesla_ABK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 18 5d 3a 09 00 00 00 06 02 58 0a 38 04 00 00 00 06 02 59 0a 07 17 58 0b 07 03 32 e3 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}