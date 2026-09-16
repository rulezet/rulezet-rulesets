rule Trojan_BAT_AgentTesla_MBGP_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.MBGP!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {52 2d 30 33 2d 52 2d 45 32 2d 52 2d 30 33 2d 52 2d 45 32 2d 52 2d 30 33 2d 52 2d 45 32 2d 52 2d 31 33 2d 52 2d 52 2d 52 2d 45 36 2d 52 2d 46 36 2d 52 2d 39 36 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}