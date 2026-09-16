rule Trojan_BAT_AgentTesla_MBES_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.MBES!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_03_0 = {0a 0d 08 09 28 ?? 00 00 06 09 [0-10] 6f ?? 00 00 0a 09 13 04 de 1c } 		$a_01_1 = {24 61 35 65 39 30 61 66 35 2d 65 30 30 61 2d 34 62 34 37 2d 39 63 36 65 2d 62 39 63 65 32 61 63 36 34 61 66 36 } 		$a_01_2 = {46 75 63 6b 2e 50 72 6f 70 65 72 74 69 65 73 } 	condition:
		((#a_03_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}