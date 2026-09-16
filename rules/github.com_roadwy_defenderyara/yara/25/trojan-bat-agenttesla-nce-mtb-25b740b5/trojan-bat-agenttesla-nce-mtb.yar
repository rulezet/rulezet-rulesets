rule Trojan_BAT_AgentTesla_NCE_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NCE!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 01 00 00 "
		
	strings :
		$a_01_0 = {07 03 74 11 00 00 1b 09 91 6f ba 00 00 0a 00 09 17 d6 0d 09 08 31 e9 } 	condition:
		((#a_01_0  & 1)*3) >=3
 
}