rule Trojan_BAT_AgentTesla_SPW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.SPW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {11 07 20 8b 18 fe f1 5a 20 40 d2 f6 f6 61 38 b7 fe ff ff 28 ?? ?? ?? 0a 7e 01 00 00 04 02 08 6f ?? ?? ?? 0a 28 ?? ?? ?? 0a a5 01 00 00 1b 0b 11 07 20 41 68 4f 51 5a 20 e0 6d 88 f0 61 38 88 fe ff ff } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}