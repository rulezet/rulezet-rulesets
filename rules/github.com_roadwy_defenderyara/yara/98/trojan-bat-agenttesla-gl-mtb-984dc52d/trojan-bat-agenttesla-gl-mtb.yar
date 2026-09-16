rule Trojan_BAT_AgentTesla_GL_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.GL!MTB,SIGNATURE_TYPE_PEHSTR_EXT,03 00 03 00 03 00 00 "
		
	strings :
		$a_02_0 = {06 11 07 7e 01 00 00 04 11 07 91 7e 01 00 00 04 16 91 61 d2 9c 11 07 17 58 13 07 20 [0-04] 20 01 00 00 00 ?? fe 0e 0b 00 } 		$a_02_1 = {48 68 d3 13 0a 38 ?? fa ff ff } 		$a_01_2 = {63 6f 73 74 75 72 61 2e 63 6f 73 74 75 72 61 2e 64 6c 6c 2e 63 6f 6d 70 72 65 73 73 65 64 } 	condition:
		((#a_02_0  & 1)*1+(#a_02_1  & 1)*1+(#a_01_2  & 1)*1) >=3
 
}