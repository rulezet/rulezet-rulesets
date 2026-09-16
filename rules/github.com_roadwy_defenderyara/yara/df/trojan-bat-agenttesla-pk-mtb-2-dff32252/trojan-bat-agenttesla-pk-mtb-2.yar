rule Trojan_BAT_AgentTesla_PK_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,0d 00 0c 00 04 00 00 "
		
	strings :
		$a_02_0 = {0b 16 02 8e b7 17 da 13 06 13 05 2b 28 07 11 05 02 11 05 91 06 61 09 08 91 61 b4 9c 08 03 6f ?? ?? ?? 0a 17 da 33 04 16 0c 2b 04 08 17 d6 0c 11 05 17 d6 13 05 11 05 11 06 31 d2 } 		$a_80_1 = {52 43 32 44 65 63 72 79 70 74 } 		$a_80_2 = {58 4f 52 5f 44 45 43 } 		$a_80_3 = {52 69 6a 6e 44 65 63 72 79 70 74 } 	condition:
		((#a_02_0  & 1)*10+(#a_80_1  & 1)*1+(#a_80_2  & 1)*1+(#a_80_3  & 1)*1) >=12
 
}