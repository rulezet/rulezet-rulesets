rule Trojan_BAT_AgentTesla_AQ_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {00 02 07 8f 10 00 00 01 25 71 10 00 00 01 06 07 00 23 [0-30] 40 23 [0-30] 40 28 ?? ?? ?? 0a 58 28 ?? ?? ?? 0a 5d 91 61 d2 81 ?? ?? ?? 01 00 07 17 58 0b 07 02 8e 69 fe 04 0d 09 2d ba } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}