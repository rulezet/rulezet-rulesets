rule Trojan_BAT_AgentTesla_GAL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.GAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,01 00 01 00 01 00 00 "
		
	strings :
		$a_03_0 = {d0 3f 00 00 01 28 33 00 00 0a 14 72 01 03 00 70 1b 8d 19 00 00 01 25 16 72 1b 03 00 70 7e 48 00 00 0a 72 21 03 00 70 28 ?? ?? ?? 0a a2 25 17 20 00 01 00 00 8c 55 00 00 01 a2 25 1a 17 8d 19 00 00 01 25 16 02 a2 a2 14 14 28 ?? ?? ?? 0a 0a 2b 00 06 2a } 	condition:
		((#a_03_0  & 1)*1) >=1
 
}