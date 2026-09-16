rule Trojan_BAT_AgentTesla_ABK_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.ABK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 03 00 00 "
		
	strings :
		$a_03_0 = {73 28 00 00 0a 0a 06 03 16 03 8e 69 6f ?? 00 00 0a 00 06 6f 2a 00 00 0a 00 00 de 05 } 		$a_01_1 = {73 6f 63 6b 65 74 70 72 6f 67 72 61 6d 69 6e 67 2e 52 65 73 6f 75 72 63 65 31 } 		$a_01_2 = {63 33 34 38 33 33 39 64 2d 31 34 32 34 2d 34 34 35 66 2d 61 66 33 35 2d 39 31 62 61 33 61 30 33 34 63 38 65 } 	condition:
		((#a_03_0  & 1)*2+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=4
 
}