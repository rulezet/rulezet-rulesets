rule Trojan_BAT_AgentTesla_AA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {73 10 00 00 06 0a 06 03 7d 0a 00 00 04 00 02 06 fe 06 11 00 00 06 73 19 00 00 0a 28 06 00 00 2b 28 07 00 00 2b 0b 2b 00 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}