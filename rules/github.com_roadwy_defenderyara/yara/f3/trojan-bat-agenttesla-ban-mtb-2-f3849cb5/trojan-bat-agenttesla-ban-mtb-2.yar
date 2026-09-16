rule Trojan_BAT_AgentTesla_BAN_MTB_2{
	meta:
		description = "Trojan:BAT/AgentTesla.BAN!MTB,SIGNATURE_TYPE_PEHSTR_EXT,02 00 02 00 02 00 00 "
		
	strings :
		$a_01_0 = {2c 05 11 3d 16 35 03 16 2b 01 17 17 59 11 39 20 e7 02 00 00 95 5f 11 39 20 43 06 00 00 95 61 58 13 2e } 		$a_01_1 = {11 1c 33 0b 11 3a 13 3a 16 11 16 13 21 2b 01 17 17 59 11 1b 20 52 09 00 00 95 5f 11 1b 20 0b 0d 00 00 95 61 58 13 19 } 	condition:
		((#a_01_0  & 1)*2+(#a_01_1  & 1)*2) >=2
 
}