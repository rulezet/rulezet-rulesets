rule Trojan_BAT_AgentTesla_AWK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AWK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 11 04 6f ?? ?? ?? 0a 13 08 08 12 08 28 ?? ?? ?? 0a 6f ?? ?? ?? 0a 00 11 04 17 58 13 04 00 11 04 07 6f ?? ?? ?? 0a fe 04 13 09 11 09 2d cf } 	condition:
		((#a_03_0  & 1)*2) >=2
 
}