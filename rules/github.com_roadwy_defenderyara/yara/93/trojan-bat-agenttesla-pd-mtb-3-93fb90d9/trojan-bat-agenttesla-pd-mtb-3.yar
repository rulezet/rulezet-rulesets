rule Trojan_BAT_AgentTesla_PD_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.PD!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 08 8f 6d 00 00 01 25 47 02 08 1f 10 5d 91 61 d2 52 00 08 17 d6 0c 08 07 fe 02 16 fe 01 0d 09 2d } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}