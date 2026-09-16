rule Trojan_BAT_AgentTesla_SQ_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SQ!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 5d 13 04 06 17 58 08 5d 13 0a 07 11 0a 91 20 00 01 00 00 58 13 0b 07 11 04 91 13 0c 11 0c 11 06 06 1f 16 5d 91 61 13 0d 11 0d 11 0b 59 13 0e 07 11 04 11 0e 20 00 01 00 00 5d d2 9c 06 17 58 0a 06 08 11 07 17 58 5a fe 04 13 0f 11 0f 2d af } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}