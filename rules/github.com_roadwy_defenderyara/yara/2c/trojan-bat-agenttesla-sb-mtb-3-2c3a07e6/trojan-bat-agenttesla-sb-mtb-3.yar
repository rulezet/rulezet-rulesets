rule Trojan_BAT_AgentTesla_SB_MTB_3{
	meta:
		description = "Trojan:BAT/AgentTesla.SB!MTB,SIGNATURE_TYPE_PEHSTR_EXT,16 00 16 00 05 00 00 "
		
	strings :
		$a_00_0 = {28 51 00 00 0a 02 d6 6c 0b 2b 0e 17 28 52 00 00 0a 00 28 53 00 00 0a 00 00 28 51 00 00 0a 6c 07 fe 04 0c 08 2d e5 } 		$a_80_1 = {43 68 65 63 6b 46 69 6c 65 4c 6f 63 61 74 69 6f 6e } 		$a_80_2 = {41 64 64 54 6f 5f 4e 6f 6e 4b 65 79 } 		$a_80_3 = {49 6e 66 6f 5f 47 72 61 62 5f 49 42 } 		$a_80_4 = {57 65 62 5f 4e 65 77 41 64 64 72 65 73 73 } 	condition:
		((#a_00_0  & 1)*10+(#a_80_1  & 1)*3+(#a_80_2  & 1)*3+(#a_80_3  & 1)*3+(#a_80_4  & 1)*3) >=22
 
}