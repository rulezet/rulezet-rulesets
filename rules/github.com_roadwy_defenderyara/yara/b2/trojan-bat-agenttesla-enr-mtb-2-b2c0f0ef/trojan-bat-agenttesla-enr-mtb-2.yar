rule Trojan_BAT_AgentTesla_ENR_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ENR!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 20 00 0a 01 00 5d 07 09 20 00 0a 01 00 5d 91 08 09 1f 16 5d 6f ?? ?? ?? 0a 61 07 09 17 58 20 00 0a 01 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}