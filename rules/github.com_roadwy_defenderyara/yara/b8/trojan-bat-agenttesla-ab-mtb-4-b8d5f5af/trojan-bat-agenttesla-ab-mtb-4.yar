rule Trojan_BAT_AgentTesla_AB_MTB_4{
	meta:
		description = "Trojan:BAT/AgentTesla.AB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 01 00 00 "
		
	strings :
		$a_03_0 = {26 11 06 20 ?? 00 00 00 91 1a 5b 13 05 2b b5 16 0a 1b 13 05 2b ae 0e 04 05 61 1f 6e 59 06 61 45 ?? ?? ?? ?? ?? ?? ?? ?? 1d 13 05 2b 97 11 06 20 dd 00 00 00 91 11 06 20 d3 00 00 00 91 59 2b e9 12 02 fe ?? 21 00 00 01 08 0b 11 06 1f 50 91 13 05 38 ?? ff ff ff 02 8c 01 00 00 1b 03 04 6f ?? 00 00 0a 0b 1a 13 05 38 ?? ff ff ff 06 17 58 0a 05 25 5a 0d 05 09 58 0d 11 06 20 f0 00 00 00 91 1f 0d 59 13 05 38 ?? ff ff ff } 	condition:
		((#a_03_0  & 1)*5) >=5
 
}