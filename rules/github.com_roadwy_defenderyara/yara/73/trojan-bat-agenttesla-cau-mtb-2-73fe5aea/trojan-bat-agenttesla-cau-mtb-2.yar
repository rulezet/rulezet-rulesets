rule Trojan_BAT_AgentTesla_CAU_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.CAU!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 03 00 00 "
		
	strings :
		$a_03_0 = {2b 41 16 6f ?? 00 00 0a 6f ?? 00 00 0a 72 ?? 00 00 70 7e ?? 00 00 0a 6f ?? 00 00 0a 28 ?? 00 00 0a 2a 73 ?? 00 00 0a 38 ?? ff ff ff 0a 38 ?? ff ff ff 06 2b c2 6f ?? 00 00 0a 2b bd 28 ?? 00 00 0a 2b bd 06 2b bc } 		$a_01_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_01_2 = {52 65 70 6c 61 63 65 } 	condition:
		((#a_03_0  & 1)*3+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=5
 
}