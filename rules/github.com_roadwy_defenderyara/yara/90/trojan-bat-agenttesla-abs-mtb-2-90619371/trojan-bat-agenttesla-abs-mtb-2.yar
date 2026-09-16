rule Trojan_BAT_AgentTesla_ABS_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.ABS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0c 00 0c 00 03 00 00 "
		
	strings :
		$a_03_0 = {11 05 11 09 8f ?? ?? ?? 01 25 47 11 08 61 d2 52 11 05 11 09 91 13 08 00 11 09 17 58 13 09 11 09 11 05 8e 69 fe 04 13 0a 11 0a 2d d3 } 		$a_01_1 = {67 65 74 5f 65 6e 63 72 79 70 74 65 64 } 		$a_01_2 = {67 65 74 5f 43 75 72 72 65 6e 74 44 6f 6d 61 69 6e } 	condition:
		((#a_03_0  & 1)*10+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=12
 
}