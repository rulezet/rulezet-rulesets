rule Trojan_BAT_AgentTesla_AW_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.AW!MTB,SIGNATURE_TYPE_PEHSTR_EXT,04 00 04 00 02 00 00 "
		
	strings :
		$a_01_0 = {20 55 01 00 00 95 e0 95 7e 0d 00 00 04 20 47 0e 00 00 95 61 7e 0d 00 00 04 20 f8 07 00 00 95 2e 03 17 2b 03 16 06 0a } 		$a_01_1 = {20 76 04 00 00 95 e0 95 7e 0d 00 00 04 20 83 01 00 00 95 61 7e 0d 00 00 04 20 2f 0d 00 00 95 2e 03 17 2b 01 16 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=4
 
}