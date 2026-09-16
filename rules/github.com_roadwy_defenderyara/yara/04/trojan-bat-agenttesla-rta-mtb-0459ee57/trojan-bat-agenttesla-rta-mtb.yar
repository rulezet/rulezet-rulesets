rule Trojan_BAT_AgentTesla_RTA_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.RTA!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_80_0 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_80_1 = {24 36 34 30 30 31 42 31 33 2d 37 30 38 35 2d 34 42 33 33 2d 38 38 34 41 2d 42 41 30 42 31 43 44 32 31 38 46 36 } 		$a_03_2 = {08 07 93 28 ?? ?? ?? 0a 1f 21 32 11 08 07 93 28 ?? ?? ?? 0a 1f 7e fe 02 16 fe 01 2b 01 16 0d 09 2c 14 08 07 1f 21 08 07 93 1f 0e 58 1f 5e 5d 58 28 ?? ?? ?? 0a 9d 07 17 58 0b 07 06 6f ?? ?? ?? 0a fe 04 13 04 11 04 2d b7 } 	condition:
		((#a_80_0  & 1)*1+(#a_80_1  & 1)*1+(#a_03_2  & 1)*1) >=3
 
}