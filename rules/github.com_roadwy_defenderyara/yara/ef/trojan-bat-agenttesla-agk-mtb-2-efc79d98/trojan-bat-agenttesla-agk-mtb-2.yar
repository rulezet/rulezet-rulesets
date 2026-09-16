rule Trojan_BAT_AgentTesla_AGK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.AGK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 11 06 03 7b 25 00 00 04 11 06 18 03 7b 23 00 00 04 5a 09 5a 58 91 9c 00 11 06 17 58 13 06 11 06 18 7e 31 00 00 04 5a fe 04 13 05 11 05 2d cf } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}