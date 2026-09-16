rule Trojan_BAT_AgentTesla_SJ_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.SJ!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {02 28 03 04 00 06 fe 0e 00 00 16 fe 0e 03 00 fe 0c 03 00 17 5a fe 0e 04 00 03 28 0b 02 00 0a fe 0e 01 00 00 00 fe 0c 00 00 8e 69 17 59 fe 0e 02 00 2b 2e fe 0c 00 00 fe 0c 02 00 fe 0c 00 00 fe 0c 02 00 91 fe 0c 01 00 fe 0c 02 00 fe 0c 01 00 8e 69 5d 91 61 d2 9c fe 0c 02 00 17 59 fe 0e 02 00 fe 0c 02 00 16 2f cb } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}