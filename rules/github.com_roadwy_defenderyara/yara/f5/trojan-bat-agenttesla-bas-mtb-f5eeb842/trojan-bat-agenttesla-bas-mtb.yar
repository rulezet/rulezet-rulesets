rule Trojan_BAT_AgentTesla_BAS_MTB{
	meta:
		description = "Trojan:BAT/AgentTesla.BAS!MTB,SIGNATURE_TYPE_PEHSTR_EXT,05 00 05 00 02 00 00 "
		
	strings :
		$a_01_0 = {95 33 56 11 4f 11 2d 2c 07 16 11 17 13 17 2b 01 17 17 59 11 4a 20 1e 10 00 00 95 5f 11 4a 20 94 13 00 00 95 61 58 13 4f } 		$a_01_1 = {17 2b 01 16 58 6a 11 4a 20 61 07 00 00 95 6e 31 03 16 2b 01 17 17 59 11 4a 20 d4 07 00 00 95 5f 11 4a 20 71 0b 00 00 95 61 58 13 4f 38 db 13 00 00 } 	condition:
		((#a_01_0  & 1)*5+(#a_01_1  & 1)*5) >=5
 
}