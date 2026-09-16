rule Trojan_BAT_AgentTesla_MBP_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {b6 00 b6 00 60 00 6c 25 71 00 51 00 88 25 88 25 88 25 88 25 4d 00 88 25 88 25 88 25 88 25 88 25 88 25 88 25 88 25 45 00 88 25 88 25 88 25 88 25 88 25 88 25 88 25 88 25 2f 00 2f 00 38 00 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}