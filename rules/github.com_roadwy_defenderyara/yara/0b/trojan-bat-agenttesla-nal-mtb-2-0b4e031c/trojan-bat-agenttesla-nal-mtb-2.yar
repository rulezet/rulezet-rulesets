rule Trojan_BAT_AgentTesla_NAL_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.NAL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0b 00 0b 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 0a 2b 0b 2b 0c 2b 11 2b 16 de 24 06 2b f3 02 2b f2 73 ?? ?? ?? 0a 2b ed 6f ?? ?? ?? 0a 2b e8 0b 2b e7 } 		$a_03_1 = {73 27 00 00 0a 0b 2b 2e 16 2b 2e 2b 33 2b 38 16 2d 09 2b 09 2b 0a 6f ?? ?? ?? 0a de 10 08 2b f4 07 2b f3 } 		$a_01_2 = {41 64 6f 62 65 20 55 70 64 61 74 65 72 20 55 74 69 6c 69 74 79 } 	condition:
		((#a_03_0  & 1)*5+(#a_03_1  & 1)*5+(#a_01_2  & 1)*1) >=11
 
}