rule Trojan_BAT_AgentTesla_PK_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.PK!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_01_0 = {ff b6 ff 09 0f 00 00 00 fa 25 33 00 16 00 00 02 00 00 00 d4 00 00 00 28 00 00 00 04 01 00 00 57 02 00 00 da 00 00 00 07 00 00 00 78 01 00 00 67 } 		$a_01_1 = {31 64 65 35 65 39 30 33 62 36 31 62 } 		$a_01_2 = {4c 43 44 2e 50 72 6f 70 65 72 74 69 65 73 } 	condition:
		((#a_01_0  & 1)*1+(#a_01_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}