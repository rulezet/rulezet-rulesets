rule Trojan_BAT_AgentTesla_FS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.FS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0d 00 04 00 00 "
		
	strings :
		$a_02_0 = {19 0a 02 13 05 16 13 04 11 05 6f ?? ?? ?? 0a 13 06 2b 2a 11 05 11 04 6f ?? ?? ?? 0a 0d 08 09 28 ?? ?? ?? 0a 06 da 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 28 ?? ?? ?? 0a 0c 11 04 17 d6 13 04 00 11 04 11 06 fe 04 13 07 11 07 2d ca } 		$a_81_1 = {46 72 6f 6d 42 61 73 65 36 34 53 74 72 69 6e 67 } 		$a_81_2 = {43 72 65 61 74 65 49 6e 73 74 61 6e 63 65 } 		$a_81_3 = {41 63 74 69 76 61 74 6f 72 } 	condition:
		((#a_02_0  & 1)*10+(#a_81_1  & 1)*1+(#a_81_2  & 1)*1+(#a_81_3  & 1)*1) >=13
 
}