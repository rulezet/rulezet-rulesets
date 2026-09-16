rule Trojan_BAT_AgentTesla_NRA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.NRA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 09 20 00 60 00 00 5d 07 09 20 00 60 00 00 5d 91 08 09 1f 16 5d 6f ?? ?? ?? 0a 61 07 09 17 58 20 00 60 00 00 5d 91 59 20 00 01 00 00 58 20 00 01 00 00 5d d2 9c 00 09 15 58 0d 09 16 fe 04 16 fe 01 13 04 11 04 2d b7 } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}