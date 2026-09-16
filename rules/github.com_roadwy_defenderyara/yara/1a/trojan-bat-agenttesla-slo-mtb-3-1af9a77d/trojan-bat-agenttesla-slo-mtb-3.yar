rule Trojan_BAT_AgentTesla_SLO_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.SLO!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 03 00 00 "
		
	strings :
		$a_00_0 = {00 20 c0 0f 00 00 28 18 00 00 0a 00 73 19 00 00 0a 0a 06 72 01 00 00 70 6f 1a 00 00 0a 0b 16 0c 2b 13 00 07 08 07 08 91 20 4e 06 00 00 59 d2 9c 08 17 58 0c 00 08 07 8e 69 fe 04 0d 09 2d e3 } 		$a_02_1 = {00 07 08 07 08 91 [0-05] 59 d2 9c 08 17 58 0c 00 08 07 8e 69 fe 04 0d 09 2d e3 } 		$a_00_2 = {24 32 37 66 33 64 62 65 65 2d 39 35 65 65 2d 34 63 66 64 2d 39 62 33 61 2d 63 30 66 38 39 35 62 61 33 30 37 63 } 	condition:
		((#a_00_0  & 1)*2+(#a_02_1  & 1)*1+(#a_00_2  & 1)*1) >=2
 
}