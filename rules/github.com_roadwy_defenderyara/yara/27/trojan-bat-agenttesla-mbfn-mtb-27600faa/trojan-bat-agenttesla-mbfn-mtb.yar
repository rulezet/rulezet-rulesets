rule Trojan_BAT_AgentTesla_MBFN_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBFN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_01_0 = {06 08 5d 13 04 06 1f 16 5d 13 0b 06 17 58 08 5d 13 0c 07 11 04 91 13 0d 20 00 01 00 00 13 05 11 0d 11 06 11 0b 91 61 07 11 0c 91 59 11 05 58 11 05 } 	condition:
		((#a_01_0  & 1)*1) >=1
 
}