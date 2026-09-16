rule Trojan_BAT_AgentTesla_AI_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AI!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {18 9a 1f 09 95 2d 03 16 2b 01 17 17 59 7e 0b 00 00 04 16 9a 20 db 01 00 00 95 5f 7e 0b 00 00 04 16 9a 20 e5 01 00 00 95 61 59 } 		$a_01_1 = {19 9a 20 01 05 00 00 95 e0 95 7e 0b 00 00 04 19 9a 20 de 0c 00 00 95 61 7e 0b 00 00 04 19 9a 20 c1 0b 00 00 95 2e 03 17 2b 01 16 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}