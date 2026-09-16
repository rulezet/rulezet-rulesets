rule Trojan_BAT_AgentTesla_MBEH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBEH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 02 00 00 "
		
	strings :
		$a_01_0 = {8e 69 6a 5d d4 91 08 11 13 08 8e 69 6a 5d d4 91 61 07 11 13 17 6a 58 07 8e 69 6a 5d d4 91 59 20 00 01 00 00 58 13 14 07 11 13 07 8e 69 6a 5d d4 11 14 20 00 01 00 00 5d } 		$a_01_1 = {8e 69 6a 5d d4 91 09 07 09 8e 69 6a 5d d4 91 61 06 07 17 6a 58 06 8e 69 6a 5d d4 91 59 20 00 01 00 00 58 13 08 07 06 8e 69 6a 5d 13 09 11 08 20 00 01 00 00 5d 13 0a 06 11 09 d4 11 0a d2 9c 07 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1) >=1
 
}