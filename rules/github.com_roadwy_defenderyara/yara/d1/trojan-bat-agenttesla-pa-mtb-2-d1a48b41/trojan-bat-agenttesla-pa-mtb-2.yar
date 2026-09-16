rule Trojan_BAT_AgentTesla_PA_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.PA!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 06 07 02 07 91 03 07 03 8e 69 5d 91 61 d2 9c 00 07 17 58 0b 07 02 8e 69 fe 04 0c 08 3a } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}