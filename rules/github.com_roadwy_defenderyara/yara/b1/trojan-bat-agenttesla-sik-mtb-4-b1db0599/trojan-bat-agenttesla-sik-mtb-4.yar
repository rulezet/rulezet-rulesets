rule Trojan_BAT_AgentTesla_SIK_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.SIK!MTB,SIGNATURE_TYPE_PEHSTR,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 07 11 0c 17 6a 58 11 08 6a 5d d4 91 13 0d 11 0d 13 0e 07 11 0c 11 08 6a 5d d4 91 13 0f 08 11 0c 69 1f 16 5d 6f 28 00 00 0a 13 10 11 0f 11 10 61 13 11 11 11 11 0e 59 13 12 11 12 20 00 01 00 00 58 20 ff 00 00 00 5f 13 12 07 11 0c 11 08 6a 5d d4 11 12 28 29 00 00 0a 9c 00 11 0c 17 6a 58 13 0c 11 0c 11 08 17 59 6a fe 02 16 fe 01 13 13 11 13 2d 8c } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}