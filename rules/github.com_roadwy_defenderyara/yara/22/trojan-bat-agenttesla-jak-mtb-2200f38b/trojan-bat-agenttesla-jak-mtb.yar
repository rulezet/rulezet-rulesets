rule Trojan_BAT_AgentTesla_JAK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.JAK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {20 00 10 00 00 8d ?? ?? ?? 01 0b 73 ?? ?? ?? 0a 0c [0-02] 06 07 16 20 00 10 00 00 6f ?? ?? ?? 0a 0d 09 16 fe 02 13 04 11 04 2c 0c 00 08 07 16 09 6f ?? ?? ?? 0a [0-03] 09 16 fe 02 13 05 11 05 2d d0 08 6f } 		$a_81_1 = {56 65 72 69 66 79 44 65 74 61 69 6c 73 } 		$a_81_2 = {44 42 5f 46 69 6e 64 65 72 } 		$a_81_3 = {41 6e 61 6c 79 69 73 65 } 	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}