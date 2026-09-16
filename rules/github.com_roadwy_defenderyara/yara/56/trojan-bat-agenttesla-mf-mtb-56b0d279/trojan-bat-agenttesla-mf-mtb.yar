rule Trojan_BAT_AgentTesla_MF_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MF!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {57 1d a2 1d 09 0b 00 00 00 fa 25 33 00 16 00 00 01 00 00 00 31 00 00 00 09 00 00 00 2b 00 00 00 38 00 00 00 1d } 		$a_03_1 = {0d 08 09 28 ?? ?? ?? 06 09 16 6a 6f ?? ?? ?? 0a 09 13 04 dd 2d 01 00 00 20 00 00 af 0d fe 0e 06 00 00 fe 0d 06 00 48 68 d3 13 05 2b 0a } 		$a_01_2 = {61 70 69 6d 69 74 } 	condition:
		((#a_01_0  & 1)*1+(#a_03_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}