rule Trojan_BAT_AgentTesla_SIK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.SIK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_00_0 = {20 00 1e 01 00 0d 16 13 06 2b 77 00 16 13 07 2b 5a 00 07 11 06 11 07 6f af 00 00 0a 13 08 08 6f b0 00 00 0a 19 58 09 fe 02 16 fe 01 13 09 11 09 2c 0d } 		$a_00_1 = {00 00 2b 25 00 09 08 6f b0 00 00 0a 59 13 0a 11 0a 16 fe 02 13 0b 11 0b 2c 0d 00 08 11 08 11 0a 28 63 00 00 06 00 00 2b 17 00 11 07 17 58 13 07 11 07 07 6f b1 00 00 0a fe 04 13 0c 11 0c 2d 96 } 		$a_01_2 = {4d 69 6e 65 53 77 65 65 70 65 72 2e 50 72 6f 70 65 72 74 69 65 73 2e 52 65 73 6f 75 72 63 65 73 2e 72 65 73 6f 75 72 63 65 73 } 	condition:
		((#a_00_0  & 1)*1+(#a_00_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}