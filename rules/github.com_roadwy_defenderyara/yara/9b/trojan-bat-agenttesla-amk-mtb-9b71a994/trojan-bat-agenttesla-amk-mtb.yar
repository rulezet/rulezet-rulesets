rule Trojan_BAT_AgentTesla_AMK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AMK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0a 00 0a 00 01 00 00 "
		
	strings :
		$a_03_0 = {02 0a 03 0b 06 8e 69 0c 16 0d 2b 14 07 09 07 09 91 06 09 08 5d 91 28 ?? ?? ?? 06 9c 09 17 58 0d 09 07 8e 69 32 e6 } 	condition:
		((#a_03_0  & 1)*10) >=10
 
}