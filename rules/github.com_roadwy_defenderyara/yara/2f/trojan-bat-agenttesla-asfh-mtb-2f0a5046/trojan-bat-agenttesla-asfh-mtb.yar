rule Trojan_BAT_AgentTesla_ASFH_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.ASFH!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {07 11 07 07 8e 69 6a 5d d4 07 11 07 07 8e 69 6a 5d d4 91 08 11 07 08 8e 69 6a 5d d4 91 61 28 ?? 00 00 0a 07 11 07 17 6a 58 07 8e 69 6a 5d d4 91 28 ?? 00 00 0a 59 20 00 01 00 00 58 20 00 01 00 00 5d 28 ?? 00 00 0a 9c } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}