rule Trojan_BAT_AgentTesla_M_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.M!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_02_0 = {07 0c 02 08 8f ?? ?? ?? 01 25 71 ?? ?? ?? 01 7e ?? ?? ?? 04 07 1f 10 5d 91 61 d2 81 ?? ?? ?? 01 07 17 58 0b 2b c9 } 	condition:
		((#a_02_0  & 1)*1) >=1
 
}