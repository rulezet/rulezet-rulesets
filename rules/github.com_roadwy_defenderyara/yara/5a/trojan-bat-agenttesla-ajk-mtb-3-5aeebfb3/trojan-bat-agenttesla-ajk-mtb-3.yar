rule Trojan_BAT_AgentTesla_AJK_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.AJK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 01 00 00 "
		
	strings :
		$a_01_0 = {00 1f 14 0a 73 e3 00 00 0a 0b 06 0c 17 0d 2b 0c 07 09 6f 12 02 00 0a 00 09 17 d6 0d 09 08 31 f0 } 	condition:
		((#a_01_0  & 1)*2) >=2
 
}